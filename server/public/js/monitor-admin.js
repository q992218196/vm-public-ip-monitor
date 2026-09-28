(() => {
    if (window.monitorShowEvidence) return;

    let pending = 0;
    let navigation = false;
    let requestController;
    const progress = document.createElement('div');
    progress.className = 'monitor-progress';
    progress.setAttribute('role', 'progressbar');
    progress.setAttribute('aria-label', '正在加载');
    document.body.append(progress);

    function updateProgress() {
        progress.classList.toggle('is-active', navigation || pending > 0);
    }

    document.addEventListener('livewire:navigate', () => {
        navigation = true;
        updateProgress();
    });
    document.addEventListener('livewire:navigated', () => {
        document.body.append(progress);
        navigation = false;
        updateProgress();
    });
    document.addEventListener('livewire:navigate-cancelled', () => {
        navigation = false;
        updateProgress();
    });
    document.addEventListener('submit', (event) => {
        if (event.target instanceof HTMLFormElement && !event.target.hasAttribute('wire:submit')) {
            navigation = true;
            updateProgress();
        }
    }, true);

    function registerLivewireProgress() {
        if (!window.Livewire?.interceptRequest || window.monitorRequestProgressRegistered) return;
        window.monitorRequestProgressRegistered = true;
        window.Livewire.interceptRequest(({onFinish}) => {
            pending++;
            updateProgress();
            onFinish(() => {
                pending = Math.max(0, pending - 1);
                updateProgress();
            });
        });
    }
    document.addEventListener('livewire:init', registerLivewireProgress);
    registerLivewireProgress();

    window.monitorShowEvidence = async (url) => {
        let dialog = document.getElementById('monitor-evidence-dialog');
        if (!dialog) {
            dialog = document.createElement('dialog');
            dialog.id = 'monitor-evidence-dialog';
            dialog.className = 'monitor-evidence-dialog';
            dialog.innerHTML = '<div class="monitor-evidence-header"><h2>记录与证据</h2><button type="button" aria-label="关闭记录与证据">关闭</button></div><p class="monitor-evidence-status" role="status"></p><pre class="monitor-evidence-content" hidden></pre>';
            dialog.querySelector('button').addEventListener('click', () => dialog.close());
            dialog.addEventListener('close', () => requestController?.abort());
            document.body.append(dialog);
        }

        requestController?.abort();
        const controller = new AbortController();
        requestController = controller;
        const status = dialog.querySelector('.monitor-evidence-status');
        const content = dialog.querySelector('.monitor-evidence-content');
        status.textContent = '正在读取这条记录…';
        content.hidden = true;
        content.textContent = '';
        if (!dialog.open) dialog.showModal();

        try {
            const response = await fetch(url, {
                credentials: 'same-origin',
                headers: {'Accept': 'application/json'},
                signal: controller.signal,
            });
            if (!response.ok) throw new Error(`读取失败（HTTP ${response.status}）`);
            const record = await response.json();
            if (!dialog.open || controller.signal.aborted) return;
            status.textContent = record.name;
            content.textContent = JSON.stringify(record.data, null, 2);
            content.hidden = false;
        } catch (error) {
            if (!controller.signal.aborted) status.textContent = error.message || '读取失败，请重试';
        }
    };
})();
