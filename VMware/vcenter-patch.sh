software-packages stage --iso --acceptEulas
software-packages list --staged
software-packages install --staged
shutdown now -r "patch reboot"