
import yaml


with open('vulnerabilities.yaml', 'r') as vulnerabilities:
    data = yaml.safe_load(vulnerabilities)
    #for name, details in data['vulnerabilities'].items():
        #print("Vuln:", name)
        #print("Status:",details['enabled'])
    

def copy_function():
    for vuln_name, details in data['vulnerabilities'].items():

        if details['enabled'] == True:
            for file_number in range(1,6):
                file = []
                python_file = 'vulns/%s-python-vuln-%s.txt' % (vuln_name,file_number)
                html_file = 'vulns/%s-html-vuln-%s.txt' % (vuln_name,file_number)
                sql_file = 'vulns/%s-sql-vuln-%s.txt' % (vuln_name,file_number)
                conf_file = 'vulns/%s-conf-vuln-%s.txt' % (vuln_name,file_number)
                docker_file = 'vulns/%s-docker-vuln-%s.txt' % (vuln_name,file_number)
                files = [python_file, html_file, sql_file, conf_file, docker_file]
                #print(files)
                for file in files:
                    try:
                        #This extracts the vulnerability (those few lines)
                        with open(file, 'r') as content:
                            next(content) #Skips the first line
                            vulnerability = content.read()
                            
                            
                        #This extracts location where the vulnerability is suppose to go.
                        with open (file, 'r') as location:
                            locations = location.readlines()[0][1::].split(',')
                            locations = [l.strip('\n') for l in locations]
                        for file in locations: 
                            with open(file, 'r+') as destination:
                                extension = file.split('.')[-1]
                                #print(file + "-> FOUND")
                                lines = destination.readlines()
                                destination.seek(0)  # This moves file pointer back to the beginning
                                mark = '%s-%s - START' % (vuln_name,file_number)

                                for line in lines:
                                        
                                    if mark in line:
                                        indentation = len(line) - len(line.lstrip())
                                        if extension == 'py':
                                            status = ' ' * indentation + '"""Status: Vulnerable"""\n'
                                            description = ' ' * indentation + '#Description: '+details['description']+'\n'
                                        elif extension == 'html':
                                            status = ' ' * indentation + '{# Status: Vulnerable #}\n'
                                            description = ' ' * indentation + f'{{#Description:  {details["description"]} #}}\n'
                                        elif extension == 'sql':
                                            status = ' ' * indentation + '--Status: Vulnerable\n'
                                            description = ' ' * indentation + '--Description: '+details['description']+'\n'
                                        else:
                                            status = ' ' * indentation + '#Status: Vulnerable\n'
                                            description = ' ' * indentation + '#Description: '+details['description']+'\n'
                                            
                                        indented_function = '\n'.join([' ' * (indentation) + l for l in vulnerability.split('\n')])
                                        destination.writelines([line, status, description ,indented_function + '\n'])
                                    else:
                                        destination.write(line)
                        
                    except FileNotFoundError:
                        #print(file + "-> NOT FOUND")
                        continue
            
        elif details['enabled'] == False:
            for file_number in range(1,6):
                file = []
                #print(attack_name)
                python_file = 'fixes/%s-python-fix-%s.txt' % (vuln_name,file_number)
                html_file = 'fixes/%s-html-fix-%s.txt' % (vuln_name,file_number)
                sql_file = 'fixes/%s-sql-fix-%s.txt' % (vuln_name,file_number)
                conf_file = 'fixes/%s-conf-fix-%s.txt' % (vuln_name,file_number)
                docker_file = 'fixes/%s-docker-fix-%s.txt' % (vuln_name,file_number)
                files = [python_file, html_file, sql_file, conf_file, docker_file]
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
                                extension = file.split('.')[-1]
                                #print(extension)
                                #print(file + "-> FOUND")
                                lines = destination.readlines()
                                destination.seek(0)  # This moves file pointer back to the beginning

                                for line in lines:
                                    mark = '%s-%s - START' % (vuln_name,file_number)

                                    if mark in line:
                                        indentation = len(line) - len(line.lstrip())
                                        if extension == 'py':
                                            status = ' ' * indentation + '"""Status: Fixed"""\n'
                                            description = ' ' * indentation + '#Description: '+details['description']+'\n'
                                        elif extension == 'html':
                                            status = ' ' * indentation + '{# Status: Fixed #}\n'
                                            description = ' ' * indentation + f'{{# Description: {details["description"]} #}}\n'
                                        elif extension == 'sql':
                                            status = ' ' * indentation + '--Status: Fixed\n'
                                            description = ' ' * indentation + '--Description: '+details['description']+'\n'
                                        else:
                                            status = ' ' * indentation + '#Status: Fixed\n'
                                            description = ' ' * indentation + '#Description: '+details['description']+'\n'

                                        indented_function = '\n'.join([' ' * (indentation) + l for l in fix.split('\n')])
                                        destination.writelines([line, status, description, indented_function + '\n'])
                                    else:
                                        destination.write(line)
                        
                    except FileNotFoundError as e:
                        #print(file + "-> NOT FOUND")
                        continue
          
        elif details['enabled'] == None:
            continue        

def delete_function():
    destination_files = ['src/controllers/authController.py', 
                         'src/templates/auth/login.html',
                         'src/templates/auth/signup.html', 
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
                         'src/__init__.py', 
                         'src/log_config.py',
                         'compose.yaml',
                         'src/routes/homeRoute.py',
                         'src/routes/adminRoute.py',
                         'src/templates/public/product.html',
                         'src/templates/public/coffee.html',
                         'database/db.sql',
                         'apache/Docker/coffee-shop.conf',
                         'src/auxiliary/custom_error_responses.py',
                         'src/templates/order/order_success.html',
                         '.env',
                         'src/auxiliary/custom_decorators.py'
                        ]
    
    for file_name in destination_files:
        for vuln_name, details in data['vulnerabilities'].items():
            for file_number in range(1,6):
                with open(file_name, 'r+') as file:
                    content = file.readlines()
                    file.seek(0)
                
                    delete_block = False  # 'Switch' that turn DELETE ON/OFF
                    
                    for line in content:
                        beginning = '%s-%s - START' % (vuln_name,file_number)
                        end =  '%s-%s - END' % (vuln_name,file_number)
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