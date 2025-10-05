# coding: utf-8
import os

os.chdir('/www/server/panel')
import json, time, public, re


class apiio_tamper_main:
    __PATH = '/www/server/panel/plugin/apiio_tamper/'

    def return_site(self, get):
        data = public.M('sites').field('name,path').select()
        ret = {}
        for i in data:
            ret[i['name']] = i['path']
        return public.returnMsg(True, ret)

    def __write_log(self, msg):
        public.WriteLog('apiio_防篡改', msg)
            
    def get_locked_dirs(self, get):
        try:
            locked_dirs_file = self.__PATH + 'locked_dirs.json'
            if not os.path.exists(locked_dirs_file):
                public.WriteFile(locked_dirs_file, '[]')
                return public.returnMsg(True, [])
                
            locked_dirs = json.loads(public.ReadFile(locked_dirs_file))
            return public.returnMsg(True, locked_dirs)
        except Exception as e:
            return public.returnMsg(False, f'获取已锁定目录列表失败: {str(e)}')
            
    def lock_dir(self, get):
        try:
            if 'path' not in get or not get.path:
                return public.returnMsg(False, '请指定要锁定的目录路径')
                
            path = get.path
            
            if not os.path.exists(path):
                return public.returnMsg(False, f'指定的目录不存在: {path}')
                
            if not os.path.isdir(path):
                return public.returnMsg(False, f'指定的路径不是目录: {path}')
                
            result = public.ExecShell(f'chattr -R +i "{path}"')
            
            if result[1]:
                return public.returnMsg(False, f'锁定目录失败: {result[1]}')
                
            locked_dirs_file = self.__PATH + 'locked_dirs.json'
            if os.path.exists(locked_dirs_file):
                locked_dirs = json.loads(public.ReadFile(locked_dirs_file))
            else:
                locked_dirs = []
                
            for item in locked_dirs:
                if item['path'] == path:
                    return public.returnMsg(True, '目录已经被锁定')
            

            config = {
                'enabled': True,
                'protected_exts': [],
                'dir_whitelist': [],
                'file_whitelist': []
            }
                    
            locked_dirs.append({
                'path': path,
                'lock_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'config': config
            })
            
            public.WriteFile(locked_dirs_file, json.dumps(locked_dirs))
            
            self.__write_log(f'锁定目录: {path}')
            
            return public.returnMsg(True, '目录已成功锁定')
        except Exception as e:
            return public.returnMsg(False, f'锁定目录失败: {str(e)}')
            
    # 防篡改功能 - 解锁目录
    def unlock_dir(self, get):
        try:
            if 'path' not in get or not get.path:
                return public.returnMsg(False, '请指定要解锁的目录路径')
                
            path = get.path
            
            if not os.path.exists(path):
                return public.returnMsg(False, f'指定的目录不存在: {path}')
                
            if not os.path.isdir(path):
                return public.returnMsg(False, f'指定的路径不是目录: {path}')
                
            result = public.ExecShell(f'chattr -R -i "{path}"')
            
            if result[1]:
                return public.returnMsg(False, f'解锁目录失败: {result[1]}')
                
            locked_dirs_file = self.__PATH + 'locked_dirs.json'
            if not os.path.exists(locked_dirs_file):
                return public.returnMsg(True, '目录已成功解锁')
                
            locked_dirs = json.loads(public.ReadFile(locked_dirs_file))
            

            new_locked_dirs = []
            for item in locked_dirs:
                if item['path'] != path:
                    new_locked_dirs.append(item)
                    

            public.WriteFile(locked_dirs_file, json.dumps(new_locked_dirs))
            
            self.__write_log(f'解锁目录: {path}')
            
            return public.returnMsg(True, '目录已成功解锁')
        except Exception as e:
            return public.returnMsg(False, f'解锁目录失败: {str(e)}')
            
    # 防篡改功能 - 更新配置
    def update_tamper_config(self, get):
        try:
            if 'path' not in get or not get.path:
                return public.returnMsg(False, '请指定要配置的目录路径')
                
            path = get.path
            
            config_data = {}
            
            if hasattr(get, 'enabled'):
                config_data['enabled'] = True if get.enabled == 'true' or get.enabled == True else False
            
            if hasattr(get, 'protected_exts'):
                try:
                    config_data['protected_exts'] = json.loads(get.protected_exts)
                except:
                    try:
                        protected_exts_str = get.protected_exts.strip()
                        if protected_exts_str:
                            config_data['protected_exts'] = json.loads(protected_exts_str)
                        else:
                            config_data['protected_exts'] = []
                    except:
                        config_data['protected_exts'] = get.protected_exts.split(',')
            
            if hasattr(get, 'dir_whitelist'):
                try:
                    config_data['dir_whitelist'] = json.loads(get.dir_whitelist)
                except:
                    try:
                        dir_whitelist_str = get.dir_whitelist.strip()
                        if dir_whitelist_str:
                            config_data['dir_whitelist'] = json.loads(dir_whitelist_str)
                        else:
                            config_data['dir_whitelist'] = []
                    except:
                        config_data['dir_whitelist'] = get.dir_whitelist.split(',')
            
            if hasattr(get, 'file_whitelist'):
                try:
                    config_data['file_whitelist'] = json.loads(get.file_whitelist)
                except:
                    try:
                        file_whitelist_str = get.file_whitelist.strip()
                        if file_whitelist_str:
                            config_data['file_whitelist'] = json.loads(file_whitelist_str)
                        else:
                            config_data['file_whitelist'] = []
                    except:
                        config_data['file_whitelist'] = get.file_whitelist.split(',')
            
            if hasattr(get, 'config'):
                try:
                    tmp_config = json.loads(get.config)
                    for key in tmp_config:
                        config_data[key] = tmp_config[key]
                except:
                    if isinstance(get.config, dict):
                        for key in get.config:
                            config_data[key] = get.config[key]
            if not config_data:
                return public.returnMsg(False, '请提供配置信息')
            
            self.__write_log(f'更新防篡改配置: {path}, 配置数据: {config_data}')
            
            locked_dirs_file = self.__PATH + 'locked_dirs.json'
            if not os.path.exists(locked_dirs_file):
                return public.returnMsg(False, '未找到锁定目录列表')
                
            locked_dirs = json.loads(public.ReadFile(locked_dirs_file))
            
            found = False
            for i in range(len(locked_dirs)):
                if locked_dirs[i]['path'] == path:
                    if 'config' not in locked_dirs[i]:
                        locked_dirs[i]['config'] = {
                            'enabled': True,
                            'protected_exts': [],
                            'dir_whitelist': [],
                            'file_whitelist': []
                        }
                    
                    old_config = locked_dirs[i]['config'].copy()
                    
                    for key in config_data:
                        locked_dirs[i]['config'][key] = config_data[key]
                    
                    public.WriteFile(locked_dirs_file, json.dumps(locked_dirs))
                    
                    need_reapply = False
                    
                    if 'enabled' in config_data:
                        need_reapply = True
                    
                    if (('protected_exts' in config_data or 'dir_whitelist' in config_data or 'file_whitelist' in config_data) 
                        and locked_dirs[i]['config']['enabled']):
                        need_reapply = True
                    
                    if need_reapply:
                        self.__write_log(f'配置已变更，重新应用防篡改规则: {path}')
                        
                        self.__unlock_files_with_config(locked_dirs[i])
                        
                        if locked_dirs[i]['config']['enabled']:
                            lock_result = self.__lock_files_with_config(locked_dirs[i])
                            if not lock_result:
                                locked_dirs[i]['config'] = old_config
                                public.WriteFile(locked_dirs_file, json.dumps(locked_dirs))
                                return public.returnMsg(False, '应用防篡改规则失败，已回滚配置')
                    
                    found = True
                    break
            
            if not found:
                return public.returnMsg(False, '未找到指定的锁定目录')
            
            self.__write_log(f'成功更新防篡改配置: {path}')
            
            return public.returnMsg(True, '配置已成功更新')
        except Exception as e:
            self.__write_log(f'更新配置失败: {str(e)}')
            return public.returnMsg(False, f'更新配置失败: {str(e)}')
    
    def __lock_files_with_config(self, dir_info):
        try:
            path = dir_info['path']
            config = dir_info['config']
            
            public.ExecShell(f'chattr -R -i "{path}"')
            
            if not config['enabled']:
                self.__write_log(f'防篡改已禁用，跳过锁定操作: {path}')
                return True
            
            protected_exts = config['protected_exts']
            
            dir_whitelist = config['dir_whitelist']
            file_whitelist = config['file_whitelist']
            
            if not protected_exts and not dir_whitelist and not file_whitelist:
                self.__write_log(f'使用快速模式锁定整个目录: {path}')
                lock_cmd = f'chattr -R +i "{path}"'
                result = public.ExecShell(lock_cmd)
                if result[1]:
                    self.__write_log(f'锁定目录失败: {path}, 错误: {result[1]}')
                    return False
                self.__write_log(f'目录防篡改锁定完成: {path}')
                return True
            
            full_file_whitelist = []
            for fw in file_whitelist:
                if not fw: 
                    continue
                if not os.path.isabs(fw):
                    full_path = os.path.normpath(os.path.join(path, fw.lstrip('/')))
                    full_file_whitelist.append(full_path)
                else:
                    full_file_whitelist.append(os.path.normpath(fw))
            
            normalized_dir_whitelist = []
            for dw in dir_whitelist:
                if not dw: 
                    continue
                norm_dw = dw
                if not norm_dw.startswith('/'):
                    norm_dw = '/' + norm_dw
                normalized_dir_whitelist.append(norm_dw)
            
            lock_mode = "所有文件" if not protected_exts else f"指定类型文件: {protected_exts}"
            self.__write_log(f'开始防篡改锁定目录: {path}, 锁定模式: {lock_mode}, 目录白名单: {normalized_dir_whitelist}, 文件白名单: {file_whitelist}')
            
            if not protected_exts and (normalized_dir_whitelist or file_whitelist):
                dirs_to_lock = []
                files_to_lock = []
                
                for root, dirs, files in os.walk(path):
                    rel_dir = root.replace(path, '')
                    if not rel_dir:
                        rel_dir = '/'
                    
                    skip_dir = False
                    for white_dir in normalized_dir_whitelist:
                        if rel_dir.startswith(white_dir):
                            skip_dir = True
                            self.__write_log(f'目录在白名单中,跳过锁定: {root}')
                            break
                    
                    if skip_dir:
                        continue
                    
                    # 添加到待锁定目录列表
                    dirs_to_lock.append(root)
                    
                    for file in files:
                        file_path = os.path.join(root, file)
                        rel_file = file_path.replace(path, '')
                        
                        if file_path in full_file_whitelist or rel_file in file_whitelist:
                            self.__write_log(f'文件在白名单中,跳过锁定: {file_path}')
                            continue
                        
                        files_to_lock.append(file_path)
                
                # 批量锁定目录
                if dirs_to_lock:
                    batch_size = 100
                    for i in range(0, len(dirs_to_lock), batch_size):
                        batch = dirs_to_lock[i:i+batch_size]
                        dirs_str = '" "'.join(batch)
                        lock_cmd = f'chattr +i "{dirs_str}"'
                        result = public.ExecShell(lock_cmd)
                        if result[1]:
                            self.__write_log(f'批量锁定目录失败，错误: {result[1]}')
                
                # 批量锁定文件
                if files_to_lock:
                    batch_size = 100
                    for i in range(0, len(files_to_lock), batch_size):
                        batch = files_to_lock[i:i+batch_size]
                        files_str = '" "'.join(batch)
                        lock_cmd = f'chattr +i "{files_str}"'
                        result = public.ExecShell(lock_cmd)
                        if result[1]:
                            self.__write_log(f'批量锁定文件失败，错误: {result[1]}')
                
                self.__write_log(f'目录防篡改锁定完成: {path}')
                return True
            
            dirs_to_lock = []
            files_to_lock = []
            
            for root, dirs, files in os.walk(path):
                rel_dir = root.replace(path, '')
                if not rel_dir:
                    rel_dir = '/'
                
                skip_dir = False
                for white_dir in normalized_dir_whitelist:
                    if rel_dir.startswith(white_dir):
                        skip_dir = True
                        self.__write_log(f'目录在白名单中,跳过锁定: {root}')
                        break
                
                if skip_dir:
                    continue
                
                dirs_to_lock.append(root)
                
                # 处理文件
                for file in files:
                    file_path = os.path.join(root, file)
                    rel_file = file_path.replace(path, '')
                    
                    if file_path in full_file_whitelist or rel_file in file_whitelist:
                        self.__write_log(f'文件在白名单中,跳过锁定: {file_path}')
                        continue
                    file_ext = os.path.splitext(file)[1].lower().strip('.')
                    if file_ext in protected_exts:
                        files_to_lock.append(file_path)
            
            # 批量锁定目录
            if dirs_to_lock:

                batch_size = 100
                for i in range(0, len(dirs_to_lock), batch_size):
                    batch = dirs_to_lock[i:i+batch_size]
                    dirs_str = '" "'.join(batch)
                    lock_cmd = f'chattr +i "{dirs_str}"'
                    result = public.ExecShell(lock_cmd)
                    if result[1]:
                        self.__write_log(f'批量锁定目录失败，错误: {result[1]}')
            
            # 批量锁定文件
            if files_to_lock:
                batch_size = 100
                for i in range(0, len(files_to_lock), batch_size):
                    batch = files_to_lock[i:i+batch_size]
                    files_str = '" "'.join(batch)
                    lock_cmd = f'chattr +i "{files_str}"'
                    result = public.ExecShell(lock_cmd)
                    if result[1]:
                        self.__write_log(f'批量锁定文件失败，错误: {result[1]}')
            
            self.__write_log(f'目录防篡改锁定完成: {path}')
            return True
        except Exception as e:
            self.__write_log(f'按配置锁定文件失败: {str(e)}')
            return False
    
    # 防篡改功能 - 根据配置解锁文件
    def __unlock_files_with_config(self, dir_info):
        try:
            path = dir_info['path']
            
            if not os.path.exists(path):
                self.__write_log(f'目录不存在，无法解锁: {path}')
                return False
                
            self.__write_log(f'开始解锁目录: {path}')
            
            unlock_cmd = f'chattr -R -i "{path}"'
            result = public.ExecShell(unlock_cmd)
            
            if result[1]:
                self.__write_log(f'解锁目录失败: {path}, 错误: {result[1]}')
                return False
                
            self.__write_log(f'目录解锁完成: {path}')
            return True
        except Exception as e:
            self.__write_log(f'按配置解锁文件失败: {str(e)}')
            return False
            
    # 防篡改功能 - 移除受保护文件类型
    def remove_protected_ext(self, get):
        try:
            if 'path' not in get or not get.path:
                return public.returnMsg(False, '请指定目录路径')
                
            if 'ext' not in get or not get.ext:
                return public.returnMsg(False, '请指定要移除的文件扩展名')
                
            path = get.path
            ext = get.ext
            
            # 读取已锁定的目录列表
            locked_dirs_file = self.__PATH + 'locked_dirs.json'
            if not os.path.exists(locked_dirs_file):
                return public.returnMsg(False, '未找到锁定目录列表')
                
            locked_dirs = json.loads(public.ReadFile(locked_dirs_file))
            
            # 查找指定目录并更新配置
            found = False
            for i in range(len(locked_dirs)):
                if locked_dirs[i]['path'] == path:
                    if 'config' not in locked_dirs[i] or 'protected_exts' not in locked_dirs[i]['config']:
                        return public.returnMsg(False, '目录配置信息不完整')
                    
                    if ext in locked_dirs[i]['config']['protected_exts']:
                        locked_dirs[i]['config']['protected_exts'].remove(ext)
                        
                        if locked_dirs[i]['config']['enabled']:
                            self.__lock_files_with_config(locked_dirs[i])
                    
                    found = True
                    break
            
            if not found:
                return public.returnMsg(False, '未找到指定的锁定目录')
            
            public.WriteFile(locked_dirs_file, json.dumps(locked_dirs))
            
            self.__write_log(f'从防篡改配置中移除文件类型 {ext}: {path}')
            
            return public.returnMsg(True, f'已成功移除文件类型 {ext}')
        except Exception as e:
            return public.returnMsg(False, f'移除文件类型失败: {str(e)}')
            
    # 防篡改功能 - 移除目录白名单
    def remove_dir_whitelist(self, get):
        try:
            if 'path' not in get or not get.path:
                return public.returnMsg(False, '请指定目录路径')
                
            if 'dir' not in get or not get.dir:
                return public.returnMsg(False, '请指定要移除的白名单目录')
                
            path = get.path
            dir_path = get.dir
            
            locked_dirs_file = self.__PATH + 'locked_dirs.json'
            if not os.path.exists(locked_dirs_file):
                return public.returnMsg(False, '未找到锁定目录列表')
                
            locked_dirs = json.loads(public.ReadFile(locked_dirs_file))
            
            found = False
            for i in range(len(locked_dirs)):
                if locked_dirs[i]['path'] == path:
                    if 'config' not in locked_dirs[i] or 'dir_whitelist' not in locked_dirs[i]['config']:
                        return public.returnMsg(False, '目录配置信息不完整')
                    
                    if dir_path in locked_dirs[i]['config']['dir_whitelist']:
                        locked_dirs[i]['config']['dir_whitelist'].remove(dir_path)
                        
                        if locked_dirs[i]['config']['enabled']:
                            self.__lock_files_with_config(locked_dirs[i])
                    
                    found = True
                    break
            
            if not found:
                return public.returnMsg(False, '未找到指定的锁定目录')
            
            public.WriteFile(locked_dirs_file, json.dumps(locked_dirs))
            
            self.__write_log(f'从防篡改配置中移除目录白名单 {dir_path}: {path}')
            
            return public.returnMsg(True, f'已成功移除目录白名单 {dir_path}')
        except Exception as e:
            return public.returnMsg(False, f'移除目录白名单失败: {str(e)}')
            
    # 防篡改功能 - 移除文件白名单
    def remove_file_whitelist(self, get):
        try:
            if 'path' not in get or not get.path:
                return public.returnMsg(False, '请指定目录路径')
                
            if 'file' not in get or not get.file:
                return public.returnMsg(False, '请指定要移除的白名单文件')
                
            path = get.path
            file_path = get.file
            
            locked_dirs_file = self.__PATH + 'locked_dirs.json'
            if not os.path.exists(locked_dirs_file):
                return public.returnMsg(False, '未找到锁定目录列表')
                
            locked_dirs = json.loads(public.ReadFile(locked_dirs_file))
            
            # 查找指定目录并更新配置
            found = False
            for i in range(len(locked_dirs)):
                if locked_dirs[i]['path'] == path:
                    if 'config' not in locked_dirs[i] or 'file_whitelist' not in locked_dirs[i]['config']:
                        return public.returnMsg(False, '目录配置信息不完整')
                    
                    if file_path in locked_dirs[i]['config']['file_whitelist']:
                        locked_dirs[i]['config']['file_whitelist'].remove(file_path)
                        
                        if locked_dirs[i]['config']['enabled']:
                            self.__lock_files_with_config(locked_dirs[i])
                    
                    found = True
                    break
            
            if not found:
                return public.returnMsg(False, '未找到指定的锁定目录')
            
            public.WriteFile(locked_dirs_file, json.dumps(locked_dirs))
            
            self.__write_log(f'从防篡改配置中移除文件白名单 {file_path}: {path}')
            
            return public.returnMsg(True, f'已成功移除文件白名单 {file_path}')
        except Exception as e:
            return public.returnMsg(False, f'移除文件白名单失败: {str(e)}')

    # 防篡改功能 - 获取特定目录的防篡改配置
    def get_tamper_config(self, get):
        try:
            if 'path' not in get or not get.path:
                return public.returnMsg(False, '请指定目录路径')
                
            path = get.path
            
            locked_dirs_file = self.__PATH + 'locked_dirs.json'
            if not os.path.exists(locked_dirs_file):
                return public.returnMsg(False, '未找到锁定目录列表')
            
            try:
                locked_dirs = json.loads(public.ReadFile(locked_dirs_file))
                if not isinstance(locked_dirs, list):
                    return public.returnMsg(False, '锁定目录数据格式错误')
            except Exception as e:
                self.__write_log(f'读取锁定目录列表失败: {str(e)}')
                return public.returnMsg(False, f'读取锁定目录列表失败: {str(e)}')
            
            # 查找指定目录
            for directory in locked_dirs:
                if directory['path'] == path:
                    # 写入日志
                    self.__write_log(f'获取目录防篡改配置: {path}')
                    
                    if 'config' not in directory:
                        directory['config'] = {
                            'enabled': True,
                            'protected_exts': [],
                            'dir_whitelist': [],
                            'file_whitelist': []
                        }
                    else:
                        if 'enabled' not in directory['config']:
                            directory['config']['enabled'] = True
                        if 'protected_exts' not in directory['config'] or not isinstance(directory['config']['protected_exts'], list):
                            directory['config']['protected_exts'] = []
                        if 'dir_whitelist' not in directory['config'] or not isinstance(directory['config']['dir_whitelist'], list):
                            directory['config']['dir_whitelist'] = []
                        if 'file_whitelist' not in directory['config'] or not isinstance(directory['config']['file_whitelist'], list):
                            directory['config']['file_whitelist'] = []
                        
                    return public.returnMsg(True, directory)
            
            return public.returnMsg(False, '未找到指定目录的配置信息')
        except Exception as e:
            self.__write_log(f'获取目录防篡改配置失败: {str(e)}')
            return public.returnMsg(False, f'获取配置失败: {str(e)}')
            
    def get_gl_logs(self, get):
        import page
        page = page.Page();
        count = public.M('logs').where('type=?', (u'apiio_防篡改',)).count();
        limit = 12;
        info = {}
        info['count'] = count
        info['row'] = limit
        info['p'] = 1
        if hasattr(get, 'p'):
            info['p'] = int(get['p'])
        info['uri'] = get
        info['return_js'] = ''
        if hasattr(get, 'tojs'):
            info['return_js'] = get.tojs

        data = {}

        # 获取分页数据
        data['page'] = page.GetPage(info, '1,2,3,4,5,8');
        data['data'] = public.M('logs').where('type=?', (u'apiio_防篡改',)).order('id desc').limit(
            str(page.SHIFT) + ',' + str(page.ROW)).field('log,addtime').select();
        return data;
            
    # 获取更新历史
    def get_update_history(self, get):
        try:
            update_history_file = self.__PATH + 'update_history.txt'
            
            if not os.path.exists(update_history_file):
                return public.returnMsg(False, '更新历史文件不存在')
                
            content = public.ReadFile(update_history_file)
            
            return public.returnMsg(True, content)
        except Exception as e:
            return public.returnMsg(False, f'获取更新历史失败: {str(e)}')