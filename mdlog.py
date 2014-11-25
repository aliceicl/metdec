from winappdbg import Color

DEBUG_MODE = True
INFO_LEVEL = 0
SUCCESS_LEVEL = 1
ERROR_LEVEL = 2

def print_console(level,message):
    if (DEBUG_MODE == False):
        return
    try:
        if Color.can_use_colors():
            # Set black background.
            Color.bk_black()
            if (level==SUCCESS_LEVEL):
                Color.green()
                Color.light()                
            elif (level==ERROR_LEVEL):
                Color.red()
                Color.light()
            else:
                Color.white()
        print message
    except:
        print message
    finally:
        Color.reset()

        
        