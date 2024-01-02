from attacks import attacks_config

def copy_function():
    for item in attacks_config.items():
        attack_name, attack_value = item

        if attack_value == True:
            for file_number in range(1,5):
                file = []
                python_file = 'vulns/%s-python-vuln-%s.txt' % (attack_name,file_number)
                html_file = 'vulns/%s-html-vuln-%s.txt' % (attack_name,file_number)
                files = [python_file, html_file]
                #print(files)
                for file in files:
                    try:
                        #This extracts the vulnerability (those few lines)
                        with open(file, 'r') as content:
                            next(content) #Skips the first line
                            vulnerability = content.read()
                            #print(content)

                        #This extracts location where the vulnerability is suppose to go.
                        with open (file, 'r') as location:
                            locations = location.readlines()[0][1::].split(',')
                            locations = [l.strip('\n') for l in locations]
                        for file in locations: 
                            with open(file, 'r+') as destination:
                                print(file + "-> FOUND")
                                lines = destination.readlines()
                                destination.seek(0)  # This moves file pointer back to the beginning
                                mark = '%s-%s - START' % (attack_name,file_number)

                                for line in lines:
                                    if mark in line:
                                        indentation = len(line) - len(line.lstrip())
                                        indented_function = '\n'.join([' ' * (indentation) + l for l in vulnerability.split('\n')])
                                        destination.writelines([line, indented_function + '\n'])
                                    else:
                                        destination.write(line)
                        
                    except FileNotFoundError:
                        print(file + "-> NOT FIND")
                        continue
            
        elif attack_value == False:
            for file_number in range(1,5):
                file = []
                #print(attack_name)
                python_file = 'fixes/%s-python-fix-%s.txt' % (attack_name,file_number)
                html_file = 'fixes/%s-html-fix-%s.txt' % (attack_name,file_number)
                files = [python_file, html_file]
                for file in files:
                    try:
                        #This extracts the fix of a vulnerability (those few lines)
                        with open(file, 'r') as content:
                            next(content) #Skips the first line
                            fix = content.read()
                            #print(content)

                        #This extracts location where the fix of a vulnerability is suppose to go.
                        with open (file, 'r') as location:
                            locations = location.readlines()[0][1::].split(',')
                            locations = [l.strip('\n') for l in locations]
                            #print(locations)
                        for file in locations: 
                            with open(file, 'r+') as destination:
                                print(file + "-> FOUND")
                                lines = destination.readlines()
                                destination.seek(0)  # This moves file pointer back to the beginning

                                for line in lines:
                                    mark = '%s-%s - START' % (attack_name,file_number)

                                    if mark in line:
                                        indentation = len(line) - len(line.lstrip())
                                        indented_function = '\n'.join([' ' * (indentation) + l for l in fix.split('\n')])
                                        destination.writelines([line, indented_function + '\n'])
                                    else:
                                        destination.write(line)
                        
                    except FileNotFoundError as e:
                        print(file + "-> NOT FIND")
                        continue
          
        elif attack_name == None:
            continue        

def delete_function():
    destination_files = ['src/controllers/authController.py', 
                         'src/templates/auth/login.html', 
                         'src/templates/public/home.html',
                         'src/templates/account/setting.html',
                         'src/routes/adminRoute.py', 
                         'src/config.py', 
                         'src/controllers/homeController.py', 
                         'src/controllers/adminController.py', 
                         'src/controllers/accountController.py', 
                         'src/templates/admin/admin_panel.html',
                         'src/templates/admin/admin_panel_add.html',
                         'src/templates/admin/admin_panel_delete.html',
                         'src/templates/admin/admin_panel_view_and_update.html',
                         'src/app.py', 
                         'src/log_config.py',
                         'compose.yaml',
                         'src/routes/homeRoute.py',
                         'src/routes/adminRoute.py',
                        ]
    
    for file_name in destination_files:
        for attac_name in attacks_config.keys():
            for file_number in range(1,5):
                with open(file_name, 'r+') as file:
                    content = file.readlines()
                    file.seek(0)
                
                    delete_block = False  # 'Switch' that turn DELETE ON/OFF
                    
                    for line in content:
                        beginning = '%s-%s - START' % (attac_name,file_number)
                        end =  '%s-%s - END' % (attac_name,file_number)
                        if beginning in line:
                            delete_block = True
                            file.write(line)
                            #continue  
                        elif end in line:
                            delete_block = False
                            #file.write(line)
                            #continue  
                        
                        if not delete_block:
                            file.write(line)
                    file.truncate()


delete_function()
copy_function()