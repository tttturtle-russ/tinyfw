cmd_/home/sxk/tinyfw/modules.order := {   echo /home/sxk/tinyfw/tinywall.ko;   echo /home/sxk/tinyfw/tinywall_nl.ko; :; } | awk '!x[$$0]++' - > /home/sxk/tinyfw/modules.order
