import os
import re
import subprocess
import shutil

def create_directory(directory_path):
    try:
        os.makedirs(directory_path, exist_ok=True)
    except OSError as e:
        # print(f"创建目录 {directory_path} 失败: {e}")
        pass

def clean_filename(filename):
    # 移除文件名中的非法字符
    return re.sub(r'[\\/*?:"<>|]', '', filename)

def copy_file(source_path, destination_path):
    try:
        shutil.copy(source_path, destination_path)
    except FileNotFoundError as e:
        # print(f"无法复制文件 {source_path} 至 {destination_path}: {e}")
        pass
    except Exception as e:
        # print(f"复制文件时出现错误: {e}")
        pass
def execute_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode("utf-8")
    except subprocess.CalledProcessError as e:
        # print(f"命令执行错误: {e}")
        return ""

def find_executables(root_dir, is_x64):
    try:
        for root, dirs, files in os.walk(root_dir):
            for file in files:
                if file.endswith(".exe"):
                    executable_path = os.path.join(root, file)
                    _x64 = "x64" if is_x64.lower() == "y" else "x86"
                    try:
                        CMD_result = execute_command(f"cd {_x64} && ZeroEye.exe {executable_path}")
                        if CMD_result.find("User DLL Name") != -1:
                            results = CMD_result.split("\n")
                            print(executable_path)
                            info_path = f"bin/{_x64}/{clean_filename(file)}".replace(".exe", "")
                            create_directory(info_path)
                            copy_file(executable_path, os.path.join(info_path, file))
                            for result in results:
                                if result.find("User DLL Name") != -1:
                                    Dll_Name = result.replace("User DLL Name: ", "").strip()
                                    clean_dll_name = clean_filename(Dll_Name)
                                    copy_file(os.path.join(root, Dll_Name), os.path.join(info_path, clean_dll_name))
                                    with open(f"{info_path}/info.txt", "w") as file:
                                        file.write(f"{root}\n{CMD_result}")
                    except Exception as e:
                        # print(f"执行命令时出现错误: {e}")
                        pass
    except Exception as e:
        pass
        # print(f"遍历文件时出现错误: {e}")

if __name__ == "__main__":
    create_directory("bin")
    try:
        root_dir = input("请输入路径：")
        is_x64 = input("是否x64[y/n]:")
        find_executables(root_dir, is_x64)
    except KeyboardInterrupt:
        print("用户终止了程序执行。")
