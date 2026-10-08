"""Persist native-fault stacks and the last completed orchestration boundary."""
from contextlib import contextmanager
import faulthandler
import json
import os
from pathlib import Path
import time


@contextmanager
def native_diagnostics(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    checkpoint_file = directory / 'native_checkpoint.json'
    was_enabled = faulthandler.is_enabled()
    with (directory / 'native_fault.log').open('a') as fault_log:
        faulthandler.enable(file=fault_log, all_threads=True)
        def checkpoint(phase, **details):
            record = {'phase': phase, 'pid': os.getpid(), 'timestamp': time.time(), **details}
            temporary = checkpoint_file.with_suffix('.json.tmp')
            temporary.write_text(json.dumps(record, sort_keys=True) + '\n')
            temporary.replace(checkpoint_file)
        checkpoint('started')
        try:
            yield checkpoint
        except BaseException as error:
            checkpoint('python_exception', exception_type=type(error).__name__)
            raise
        finally:
            # Do not leave a native signal handler pointing at a closed fd.
            faulthandler.disable()
            if was_enabled:
                # Captured/embedded sys.stderr can lack fileno(). Restore the
                # process stderr descriptor, not an arbitrary Python stream.
                faulthandler.enable(file=2, all_threads=True)
