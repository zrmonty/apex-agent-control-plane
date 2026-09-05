import { requireValue } from './policy.mjs';

// Input is never line-buffered without a bound and never reflected in errors.
export function parentProtocol(input, output, abort, waitMs = 20_000) {
  let phase = 0; let pending; let bytes = ''; let timer;
  const cancel = () => abort.abort(new Error('protocol'));
  const aborted = () => {
    clearTimeout(timer);
    pending?.reject(new Error('protocol')); pending = undefined;
  };
  const data = chunk => {
    if (!pending || chunk.length + bytes.length > 2) { cancel(); return; }
    if ([...chunk].some(byte => byte > 127)) { cancel(); return; }
    bytes += chunk.toString('ascii');
    const wanted = phase === 0 ? 'D\n' : 'R\n';
    if (!wanted.startsWith(bytes)) { cancel(); return; }
    if (bytes === wanted) {
      clearTimeout(timer); const current = pending; pending = undefined; bytes = ''; phase++;
      current.resolve();
    }
  };
  input.on('data', data); input.on('end', cancel); input.on('error', cancel); input.on('close', cancel);
  output.on('error', cancel); abort.signal.addEventListener('abort', aborted);
  return {
    exchange(expected) {
      requireValue(!pending && !abort.signal.aborted && expected === (phase === 0 ? 'D' : phase === 1 ? 'R' : ''), 'protocol');
      const promise = new Promise((resolve, reject) => { pending = { resolve, reject }; });
      timer = setTimeout(cancel, waitMs);
      output.write(phase === 0 ? 'UI_READY_FOR_RESTART\n' : 'UI_OFFLINE_OBSERVED\n');
      return promise;
    },
    passed() {
      requireValue(phase === 2 && !pending && !abort.signal.aborted, 'protocol');
      phase++;
      output.write('UI_JOURNEY_PASSED\n');
    },
    dispose() {
      clearTimeout(timer); input.off('data', data); input.off('end', cancel); input.off('error', cancel);
      input.off('close', cancel); output.off('error', cancel); abort.signal.removeEventListener('abort', aborted);
      input.pause();
    },
  };
}
