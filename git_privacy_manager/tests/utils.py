from pathlib import Path
import shutil
import tempfile
from typing import List
import uuid  # Used to generate random string


def add_file(working_directory):
    file_data = str(uuid.uuid4())
    file_handle, file_path = tempfile.mkstemp(dir=working_directory, text=True)
    with open(file_handle, 'w') as f:
        f.write(file_data)

    return Path(file_path), file_data


def copy_files(src_dir: Path, dst_dir: Path):
    for f in get_all_files(src_dir):
        name = f.name
        dst = dst_dir / name
        shutil.copyfile(f, dst)


def files_in_directory(path: Path):
    all_files = path.rglob('*')
    return len([f for f in all_files if f.is_file()])


def get_all_files(path: Path) -> List[Path]:
    all_files = path.rglob('*')
    return [f for f in all_files if f.is_file() and path == f.parent]
