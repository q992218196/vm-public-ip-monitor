<?php

namespace App\Console\Commands;

use App\Models\User;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Hash;

class CreateAdmin extends Command
{
    protected $signature = 'monitor:admin {email} {--name=管理员} {--role=admin : admin or viewer}';

    protected $description = 'Create an administrator, password entered privately';

    public function handle(): int
    {
        if (! in_array($this->option('role'), ['admin', 'viewer'], true)) {
            $this->error('角色仅允许 admin 或 viewer');

            return self::FAILURE;
        }
        if (! filter_var($this->argument('email'), FILTER_VALIDATE_EMAIL) || User::where('email', $this->argument('email'))->exists()) {
            $this->error('邮箱无效或已存在');

            return self::FAILURE;
        }
        $password = $this->secret('密码（至少12位）');
        if (strlen($password ?? '') < 12) {
            $this->error('密码过短');

            return self::FAILURE;
        }
        $user = new User;
        $user->name = $this->option('name');
        $user->email = $this->argument('email');
        $user->password = Hash::make($password);
        $user->role = $this->option('role');
        $user->save();
        $this->info('用户已建立');

        return self::SUCCESS;
    }
}
