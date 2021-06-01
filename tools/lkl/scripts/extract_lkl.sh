#!/usr/bin/env bash

# Author : Parth Pratim Chatterjee (parth27official@gmail.com)

ctags -x --c-kinds=p --language-force=C include/lkl.h | awk -F ' ' '    
    function get_last_char(str){            
        len = length(str)    
        ch = substr(str,len)
        return ch
    }
    { 
    fx_definition = ""
    fx_handler = ""
    line_no = 1    
    cmd = "wc -l "$4
    while ( ( cmd | getline result ) > 0 ) {        
        split(result, a , " ")    
        total_lines = a[1]        
    }
    close(cmd);

    while ((getline line < $4) > 0)
    {
        lkl_header[line_no++] = line        
    }    

    for(i = 5 ; i <= NF ; ++i) 
    {   
        possible_fx = substr($i,0,length($1))
        possible_ptr_fx = substr($i,2,length($1))
        rem_def = substr($i,length($1)+1)                        
        rem_def_ptr_fx = substr($i,length($1)+2)          
        if(possible_fx == $1){
            fx_definition = fx_definition "(*dce_" possible_fx ")" rem_def " "
            fx_handler = fx_handler "kernelHandle->" "dce_" possible_fx "=" possible_fx ";"
        }
        else if(possible_ptr_fx == $1){
            fx_definition = fx_definition "* (*dce_" possible_ptr_fx ")" rem_def_ptr_fx " "
            fx_handler = fx_handler "kernelHandle->" "dce_" possible_ptr_fx "=" possible_ptr_fx ";"
        }
        else{
            fx_definition = fx_definition  $i " "
        }
    }     
    sub(/[ \t]+$/,"",fx_definition) 
    if(get_last_char(fx_definition) != ";"){        
        #Incomplete function definition, need to fetch more from source        
        look_from_line = $3+1             
        for(j = look_from_line ; j <= total_lines ; ++j){
            code = lkl_header[j]            
            gsub(/^[ \t]+/,"",code)
            fx_definition = fx_definition code " "            
            last_char = get_last_char(code)
            # Assuming consistent indentation and styling has been applied            
            if(last_char == ";"){                
                break
            }
        }
    }
    sub(/[ \t]+$/,"",fx_definition)
    print fx_definition > "include/lkl_kernel_handle_api_generated.h"
    print fx_handler > "lib/kernel_handle_assignment_generated.c"
}'  



