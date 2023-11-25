from attacks import attacks_config

def copy_function():
    for item in attacks_config.items():
        attack_name, attack_value = item

        if attack_value == True:
            
            python_file = 'vulns/%s-python-vuln.txt' % attack_name
            html_file = 'vulns/%s-html-vuln.txt' % attack_name
            files = [python_file, html_file]
            for file in files:
                try:
                    #This extracts the vulnerability (those few lines)
                    with open(file, 'r') as content:
                        next(content) #Skips the first line
                        vulnerability = content.read()
                        print(content)

                    #This extracts location where the vulnerability is suppose to go.
                    with open (file, 'r') as location:
                        location = location.readlines()[0][1::].strip('\n')
                        print(location)
                    
                    with open(location, 'r+') as destination:
                        lines = destination.readlines()
                        destination.seek(0)  # This moves file pointer back to the beginning
                        mark = '%s - START' % attack_name

                        for line in lines:
                            if mark in line:
                                indentation = len(line) - len(line.lstrip())
                                indented_function = '\n'.join([' ' * (indentation) + l for l in vulnerability.split('\n')])
                                destination.writelines([line, indented_function + '\n'])
                            else:
                                destination.write(line)
                    
                except FileNotFoundError:
                    continue
            
        elif attack_value == False:
            print(attack_name)
            python_file = 'fixes/%s-python-fix.txt' % attack_name
            html_file = 'fixes/%s-html-fix.txt' % attack_name
            files = [python_file, html_file]
            for file in files:
                try:
                    #This extracts the fix of a vulnerability (those few lines)
                    with open(file, 'r') as content:
                        next(content) #Skips the first line
                        fix = content.read()
                        print(content)

                    #This extracts location where the fix of a vulnerability is suppose to go.
                    with open (file, 'r') as location:
                        location = location.readlines()[0][1::].strip('\n')
                        print(location)
                    
                    with open(location, 'r+') as destination:
                        lines = destination.readlines()
                        destination.seek(0)  # This moves file pointer back to the beginning

                        for line in lines:
                            mark = '%s - START' % attack_name

                            if mark in line:
                                indentation = len(line) - len(line.lstrip())
                                indented_function = '\n'.join([' ' * (indentation) + l for l in fix.split('\n')])
                                destination.writelines([line, indented_function + '\n'])
                            else:
                                destination.write(line)
                    
                except FileNotFoundError:
                    continue
                

def delete_function():
    destination_files = ['src/controllers/authController.py', 'src/templates/auth/login.html', 'src/routes/adminRoute.py', 'src/config.py']
    
    for file_name in destination_files:
        for attac_name in attacks_config.keys():
            with open(file_name, 'r+') as file:
                content = file.readlines()
                file.seek(0)
            
                delete_block = False  # Flag to indicate if the block should be deleted
                
                for line in content:
                    beginning = '%s - START' % attac_name
                    end =  '%s - END' % attac_name
                    if beginning in line:
                        delete_block = True
                        file.write(line)
                        #continue  # Skip writing the start marker to the file
                    elif end in line:
                        delete_block = False
                        #file.write(line)
                        #continue  # Skip writing the end marker to the file
                    
                    if not delete_block:
                        file.write(line)
            
                file.truncate()

# Example usage
delete_function()
#copy_function()