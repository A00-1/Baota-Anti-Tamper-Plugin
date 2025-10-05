#!/bin/bash
PATH=/www/server/panel/pyenv/bin:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#配置插件安装目录
pluginPath=/www/server/panel/plugin/apiio_tamper

#安装
Install_tamper()
{	
	echo '安装完成OK'
}

#卸载
UnInstall_tamper()
{
	rm -rf $pluginPath
}

#操作判断
if [ "${1}" == 'install' ];then
	Install_tamper
elif [ "${1}" == 'uninstall' ];then
	UnInstall_tamper
else
	echo 'Error!';
fi



