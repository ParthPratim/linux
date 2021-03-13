#Taken from https://github.com/teto/linux/blob/dce/tools/lkl/scripts/grep_lkl.sh

#!/usr/bin/env bash
# this script aims at parsing the Linux Kernel Library (LKL) header to autmatically
# generate a structure with pointers towards lkl functions.
#
# LKLDIR="$HOME/lkl"
LKL_ROOT=$PWD

# lkl_sys_lseek
# lkl_netdev_dpdk_create
# be careful ctags can cut the
# see http://docs.ctags.io/en/latest/news.html#customizing-xref-output
# for the format
# ctags -x --c-kinds=fp "$HEADER"|tr -s '[:blank:]'|cut -d ' ' -f 5-| tee $TMPDIR/ctags.log
cd "$LKL_ROOT/tools/lkl"

# la on veut la valeur de retour
# %{C.properties}
# if I usee xargs -d then I don't need to escape arguments
# typeref is not fixed yet
ctags -x --c-kinds=fp  --_xformat="%N:%{typeref}:%{signature}" include/lkl.h > name_ret_params.csv

# xargs -d':' -a name_ret_params.csv
# todo use tempdir ?
rm -f lib/kerenl_handle_assignment_generated.c
rm -f include/lkl_kernel_handle_api_generated.c
# rm exports.generated.[hc]
while IFS=':' read name rtype signature
do
    # ./gen_struct.sh "$name" "$signature"
    echo "kernelHandle->dce_${name}=$name;" >> lib/kernel_handle_assignment_generated.c
    echo "${rtype} (*dce_${name})$signature;"  >> include/lkl_kernel_handle_api_generated.h
done < <(cat name_ret_params.csv)

echo "head $PWD/lib/exports.generated.c"
echo "head $PWD/include/lkl_exports.generated.h"

#|xargs -d':' -n 2 ./gen_struct.sh

# head name_ret_params.csv|cut -d ':'
# -p for print
# cat out.temp | perl -pe "s/(?'ret'.*)lkl_(?'name'\w*)\((?'args'.*)\)/${ret} dce_$+{name}($+{args})/"
# error on lkl_mount_dev
# cat out.temp | perl -pe "s/(?'ret'.*)lkl_(?'name'\w*)\((?'args'.*)\)/$+{ret}:$+{name}:$+{args}/g" > lkl.csv

# https://regex101.com/r/AXEXtm/1


# |xargs toto.sh

