cmd_/home/sxk/tinyfw/Module.symvers := sed 's/\.ko$$/\.o/' /home/sxk/tinyfw/modules.order | scripts/mod/modpost -m -a  -o /home/sxk/tinyfw/Module.symvers -e -i Module.symvers   -T -
