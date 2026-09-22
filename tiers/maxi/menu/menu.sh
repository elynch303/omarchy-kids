# omarchy-kids-tier-menu (marker: omarchy-kids-set-tier only removes or replaces a file that contains this line)
#
# Omarchy Kids, tier maxi. Installed by omarchy-kids-set-tier as
# ~/.config/omarchy/extensions/menu.sh, which omarchy-menu sources after
# defining its own functions, so the redefinition below wins.
#
# This account has no admin rights, so the normal Install menu could only
# fail. It asks a parent instead: see tiers/omarchy-kids-request-install.
show_install_menu() {
  present_terminal omarchy-kids-request-install
}
