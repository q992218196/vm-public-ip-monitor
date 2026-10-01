<?php

namespace App\Http\Controllers;

use App\Jobs\SummarizeCapture;
use App\Models\Node;
use App\Models\PacketCapture;
use App\Support\Ip;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Validator;

class CaptureController extends Controller
{
    public function claim(Request $request): JsonResponse
    {
        $node = $request->attributes->get('node');

        return DB::transaction(function () use ($node) {
            Node::whereKey($node->id)->lockForUpdate()->firstOrFail();
            PacketCapture::where('node_id', $node->id)->where('status', 'leased')->where('lease_until', '<', now())->update(['status' => 'failed', 'last_error' => '采集租约过期；需要人工重新申请']);
            if (PacketCapture::where('node_id', $node->id)->where('status', 'leased')->exists()) {
                return response()->json(['task' => null]);
            }
            $capture = PacketCapture::where('node_id', $node->id)->where('status', 'pending')->orderBy('created_at')->lockForUpdate()->first();
            if (! $capture) {
                return response()->json(['task' => null]);
            }
            $reserved = PacketCapture::where('status', 'leased')->sum('max_bytes');
            if (PacketCapture::whereNotNull('path')->sum('bytes') + $reserved + $capture->max_bytes > config('monitor.capture_bytes')) {
                return response()->json(['task' => null]);
            }
            abort_unless(collect($node->cidrs)->contains(fn ($cidr) => Ip::contains($cidr, $capture->ip)), 422);
            $capture->update(['status' => 'leased', 'lease_token' => bin2hex(random_bytes(32)), 'lease_until' => now()->addMinutes(10)]);

            return response()->json(['task' => ['id' => $capture->id, 'ip' => $capture->ip, 'lease_token' => $capture->lease_token, 'duration_seconds' => $capture->duration_seconds, 'max_bytes' => $capture->max_bytes, 'snaplen' => $capture->snaplen]]);
        });
    }

    public function complete(Request $request, string $id): JsonResponse
    {
        $node = $request->attributes->get('node');
        $capture = PacketCapture::whereKey($id)->where('node_id', $node->id)->firstOrFail();
        abort_unless($capture->lease_token && hash_equals($capture->lease_token, $request->header('X-Capture-Lease', '')), 409);
        if ($capture->status === 'uploaded') {
            return response()->json(['stored' => true]);
        }
        abort_unless($capture->status === 'leased' && $capture->lease_until->isFuture(), 409);
        if ($request->header('X-Capture-Failure')) {
            $capture->update(['status' => 'failed', 'last_error' => mb_substr($request->header('X-Capture-Failure'), 0, 255)]);

            return response()->json(['stored' => false]);
        }
        abort_unless(strlen($request->header('X-Capture-Metadata', '')) <= 8192, 422);
        $metadata = json_decode(base64_decode($request->header('X-Capture-Metadata', ''), true) ?: '', true);
        abort_unless(is_array($metadata), 422);
        $metadata = Validator::make($metadata, [
            'packets' => 'required|integer|min:0', 'queue_drops' => 'required|integer|min:0',
            'snaplen_truncated' => 'required|integer|min:0', 'started_at' => 'required|date', 'ended_at' => 'required|date',
            'kernel_drops_observed' => 'nullable|integer|min:0',
            'stop_reason' => 'required|in:duration,size,shutdown', 'interfaces' => 'required|array|max:8',
            'interfaces.*' => 'string|max:64',
        ])->validate();
        $path = 'packet-evidence/'.$capture->id.'.pcap';
        $disk = Storage::disk('local');
        $disk->makeDirectory('packet-evidence');
        $temp = $disk->path($path.'.'.bin2hex(random_bytes(8)).'.part');
        $input = $request->getContent(true);
        $output = fopen($temp, 'wb');
        abort_unless($output !== false, 507);
        try {
            $bytes = stream_copy_to_stream($input, $output, $capture->max_bytes + 1);
        } finally {
            fclose($output);
            if (is_resource($input)) {
                fclose($input);
            }
        }
        if ($bytes === false || $bytes < 24 || $bytes > $capture->max_bytes) {
            @unlink($temp);
            abort(413);
        }
        $header = file_get_contents($temp, false, null, 0, 24);
        if (substr($header, 0, 4) !== "\xd4\xc3\xb2\xa1" || unpack('V', substr($header, 20, 4))[1] !== 1) {
            @unlink($temp);
            abort(422, 'Only Ethernet microsecond little-endian PCAP is accepted');
        }
        $sha = hash_file('sha256', $temp);
        try {
            Cache::lock('packet-evidence-quota', 30)->block(5, function () use ($capture, $disk, $path, $temp, $sha, $bytes, $metadata) {
                DB::transaction(function () use ($capture, $disk, $path, $temp, $sha, $bytes, $metadata) {
                    $locked = PacketCapture::whereKey($capture->id)->lockForUpdate()->firstOrFail();
                    abort_unless($locked->status === 'leased' && $locked->lease_until->isFuture(), 409);
                    $archiveBytes = 0;
                    $archiveFiles = 0;
                    foreach (new \DirectoryIterator(dirname($temp)) as $entry) {
                        if ($entry->isFile() && str_ends_with($entry->getFilename(), '.pcap')) {
                            $archiveBytes += $entry->getSize();
                            $archiveFiles++;
                        }
                    }
                    abort_if($archiveBytes + $bytes > config('monitor.capture_bytes') || $archiveFiles >= 10000, 507);
                    abort_unless(rename($temp, $disk->path($path)), 507);
                    chmod($disk->path($path), 0600);
                    $locked->update(['status' => 'uploaded', 'path' => $path, 'bytes' => $bytes, 'sha256' => $sha, 'metadata' => $metadata]);
                });
            });
        } finally {
            @unlink($temp);
        }
        SummarizeCapture::dispatch($capture->id)->afterCommit();

        return response()->json(['stored' => true, 'sha256' => $sha]);
    }
}
