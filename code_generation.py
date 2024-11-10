
import yaml


class CodeGeneration():
    def __init__(self):
        with open('vulnerabilities.yaml', 'r') as file:
            self.config = yaml.safe_load(file)

    def copy_lines(self):
        for vuln_name, details in self.config['vulnerabilities'].items():
            if details['enabled'] == True:
                for file_number in range(1,6):
                    file = []
                    python_file = 'vulns/%s-python-vuln-%s.txt' % (vuln_name,file_number)
                    html_file = 'vulns/%s-html-vuln-%s.txt' % (vuln_name,file_number)
                    sql_file = 'vulns/%s-sql-vuln-%s.txt' % (vuln_name,file_number)
                    conf_file = 'vulns/%s-conf-vuln-%s.txt' % (vuln_name,file_number)
                    docker_file = 'vulns/%s-docker-vuln-%s.txt' % (vuln_name,file_number)
                    files = [python_file, html_file, sql_file, conf_file, docker_file]
                    for file in files:
                        try:
                            # This extracts the vulnerability (those few lines)
                            with open(file, 'r') as content:
                                next(content) #Skips the first line
                                vulnerability = content.read()
                                 
                            # This extracts location where the vulnerability is suppose to go.
                            with open (file, 'r') as location:
                                locations = [l.strip('\n') for l in location.readlines()[0][1::].split(',')]
                            for file in locations: 
                                with open(file, 'r+') as destination:
                                    extension = file.split('.')[-1]
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
                            # This extracts the fix of a vulnerability (those few lines)
                            with open(file, 'r') as content:
                                next(content) #Skips the first line
                                fix = content.read()

                            # This extracts location where the fix of the vulnerability is suppose to go.
                            with open (file, 'r') as location:
                                locations = [l.strip('\n') for l in location.readlines()[0][1::].split(',')]
                            for file in locations: 
                                with open(file, 'r+') as destination:
                                    extension = file.split('.')[-1]
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
                            
                        except FileNotFoundError:
                            continue
            
            elif details['enabled'] == None:
                continue 

    def delete_lines(self):
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
            for vuln_name, details in self.config['vulnerabilities'].items():
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
                            elif end in line:
                                delete_block = False
                            
                            if not delete_block:
                                file.write(line)
                        file.truncate()


def main():
    global SCRIPTNAME
    SCRIPTNAME = "CodeGeneration"
    script = CodeGeneration()
    script.delete_lines()
    script.copy_lines()

if __name__ == "__main__":
    main()
