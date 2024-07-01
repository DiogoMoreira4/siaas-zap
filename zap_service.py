import configparser
import os
import subprocess
import yaml
from zapv2 import ZAPv2
import pymongo
import time
import shutil
import click
import logging
import psutil
import signal
import siaas_aux

logging.basicConfig(filename='zap_manager.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def read_config(file_path, section, field):
    config = configparser.ConfigParser(interpolation=None)
    config.read(file_path)

    if config.has_section(section):
        return config.get(section, field, fallback=None)
    else:
        return None


def read_targets(file_path):
    config = configparser.ConfigParser(interpolation=None)
    config.read(file_path)
    targets = {}
    for section in config.sections():
        items = dict(config.items(section))
        auth_required_fields = ['username', 'password', 'loginpage']
        items['has_auth'] = all(field in items for field in auth_required_fields)
        targets[section] = items
    return targets


def start_zap_instance(port, directory):
    if not os.path.exists(directory):
        os.makedirs(directory)
        # Set ownership and permissions
        shutil.chown(directory, user='vboxuser', group='vboxuser')
        os.chmod(directory, 0o755)
    command = f"/home/vboxuser/zaproxy/zap.sh -daemon -port {port} -dir {directory} -config api.key=123456789"
    process = subprocess.Popen(command.split())
    return process


def modify_automation_plan(template_with_auth_path, template_without_auth_path, output_path, target):
    if target['has_auth']:
        template_path = template_with_auth_path
    else:
        template_path = template_without_auth_path
        
    with open(template_path, 'r') as file:
        dados_yaml = yaml.safe_load(file)
    
    if target['has_auth']:
        if 'env' in dados_yaml and 'contexts' in dados_yaml['env']:
            for aux in dados_yaml['env']['contexts']:
                aux['name'] = target['name']
                aux['urls'] = [target['url']]
                aux['includePaths'] = [target['url']+ '.*'] 
                aux['authentication']['parameters']['loginPageUrl'] = target['loginpage']
                aux['users'][0]['name'] = target['username']
                aux['users'][0]['credentials']['username'] = target['username']
                aux['users'][0]['credentials']['password'] = target['password']
        if 'jobs' in dados_yaml:
            #requestor
            dados_yaml['jobs'][1]['parameters']['user'] = target['username']
            dados_yaml['jobs'][1]['requests'][0]['url'] = target['loginpage']
            #spider
            dados_yaml['jobs'][2]['parameters']['context'] = target['name']
            dados_yaml['jobs'][2]['parameters']['user'] = target['username']
            #spiderAjax
            dados_yaml['jobs'][3]['parameters']['context'] = target['name']
            dados_yaml['jobs'][3]['parameters']['user'] = target['username']
            #delay
            #passiveScan-wait
            #activeScan
            dados_yaml['jobs'][6]['parameters']['context'] = target['name']
            dados_yaml['jobs'][6]['parameters']['user'] = target['username']
            #report
            dados_yaml['jobs'][7]['parameters']['reportFile'] = target['name']
        
    else:
        if 'env' in dados_yaml and 'contexts' in dados_yaml['env']:
            for aux in dados_yaml['env']['contexts']:
                aux['name'] = target['name']
                aux['urls'] = [target['url']]
                aux['includePaths'] = [target['url']+ '.*'] 
        if 'jobs' in dados_yaml:
            #spider
            dados_yaml['jobs'][1]['parameters']['context'] = target['name']
            #spiderAjax
            dados_yaml['jobs'][2]['parameters']['context'] = target['name']
            #passiveScan-wait
            #activeScan
            dados_yaml['jobs'][4]['parameters']['context'] = target['name']
            #report
            dados_yaml['jobs'][5]['parameters']['reportFile'] = target['name'] + "_without_auth"  
                
    with open(output_path, 'w') as file:
        yaml.safe_dump(dados_yaml, file)


def run_scan(zap, plan_path, session_name):
    zap.core.new_session(name=session_name, overwrite=True)
    zap.automation.run_plan(plan_path)
    
    
def wait_for_zap_start(port, timeout=180):
    zap = ZAPv2(apikey='123456789', proxies={'http': f'http://localhost:{port}', 'https': f'http://localhost:{port}'})
    for _ in range(timeout):
        try:
            if zap.core.version:
                return zap
        except:
            time.sleep(1)
    raise Exception(f"ZAP instance on port {port} did not start within {timeout} seconds")


def is_scan_complete(zap):
    progress = zap.automation.plan_progress(0)
    return progress['finished'] != ""


def collect_results(zap, context_name):
    urls = zap.core.urls()
    alerts = zap.core.alerts(baseurl=None)
    plan = zap.automation.plan_progress(0)
    results = {
        "target": context_name,
        "urls": urls,
        "alerts": alerts,
        "plan": plan
    }
    return results

#def save_to_mongodb(results, db):
#    collection = db["zap_results"]
#    collection.insert_one(results)

class ZAPManager:
    def __init__(self, targets_file):
        config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'conf', 'config.ini')
        self.targets_file = targets_file
        self.base_port = read_config(config_file, 'ZAPConfig', 'base_port')
        self.base_dir = read_config(config_file, 'ZAPConfig', 'base_dir')
        self.pid_file = read_config(config_file, 'ZAPConfig', 'pid_file')
        self.api_uri = read_config(config_file, 'APIconfig', 'api_uri')
        self.api_user = read_config(config_file, 'APIconfig', 'api_user')
        self.api_password = read_config(config_file, 'APIconfig', 'api_pwd')
        self.api_ssl_ignore = read_config(config_file, 'APIconfig', 'api_ssl_ignore_verify')
        self.api_ssl_ca_bundle = read_config(config_file, 'APIconfig', 'api_ssl_ca_bundle')
        self.targets = read_targets(targets_file)
        self.zap_instances = {}
        #self.collection = siaas_aux.connect_mongodb_collection(self.mongo_user, self.mongo_password, self.mongo_host, self.mongo_db, self.mongo_collection)
        
        self.current_target = None
        self._create_pid_file()

    def _create_pid_file(self):
        try:
            with open(self.pid_file, 'w') as f:
                f.write(str(os.getpid()))
        except PermissionError:
            alternate_pid_file = os.path.expanduser('~/zap_manager.pid')
            with open(alternate_pid_file, 'w') as f:
                f.write(str(os.getpid()))
            self.pid_file = alternate_pid_file

    def _remove_pid_file(self):
        if os.path.exists(self.pid_file):
            os.remove(self.pid_file)

    def start_instances(self):
        logging.info(f"Targets para analisar: {self.targets}")
        try:
            target_keys = list(self.targets.keys())
            for idx, target_key in enumerate(target_keys):
                target = self.targets[target_key]
                self.current_target = target  # Atualize o alvo atual
                port = int(self.base_port) + idx
                directory = f"{self.base_dir}{idx}"
                process = start_zap_instance(port, directory)
                self.zap_instances[target['name']] = {"port": port, "directory": directory}
                logging.info(f"Criei a instancia {idx}")
          
                
                # Start the scan
                zap = wait_for_zap_start(port)
                logging.info(f"Conectei-me a instancia {idx}")
                plan_path = f"{directory}/automation_plan.yaml"
                modify_automation_plan("/home/vboxuser/Desktop/siaas-zap/CorreuBem.yaml","/home/vboxuser/Desktop/siaas-zap/PlanWithoutAuth.yaml" ,plan_path, target)
                logging.info("Modifiquei o plano de automacao")
                session_name = f"session_{target['name']}_{port}"
                run_scan(zap, plan_path, session_name)
                
                while not is_scan_complete(zap):
                    logging.info(f"Esperando a conclusão do scan do target {target['name']}...")
                    time.sleep(300)  # Aguarde 10 minutos antes de verificar novamente
                
                results = collect_results(zap, target['name'])
                #save_to_mongodb(results, self.db)
                #siaas_aux.insert_in_mongodb_collection(self.collection, results)
                siaas_aux.post_request_to_server(self.api_uri+"/siaas-server/siaas-zap/results", results, ignore_ssl=True, ca_bundle=self.api_ssl_ca_bundle, api_user=self.api_user, api_pwd=self.api_password)
                logging.info(f"Enviei um request para a API com os resultados do {target['name']}!!!!!")
                del self.zap_instances[target['name']]
                os.kill(process.pid, signal.SIGTERM)
                logging.info(f"Parei a instancia zap da porta {port}")
                
            # Se não houver mais targets, finalize o serviço
            logging.info("Todos os targets foram analisados. Finalizando o serviço.")
            print("Todos os targets foram analisados. Finalizando o serviço.")
            self.stop_service()
        finally:
            self._remove_pid_file()

    def stop_service(self):
        with open(self.pid_file, 'r') as f:
            pid = int(f.read().strip())
        os.kill(pid, 15)  # Envia o sinal TERM para o processo

    def get_scan_progress(self):
        if not self.current_target:
            return "Nenhum scan em andamento"
        
        target = self.current_target
        instance = self.zap_instances.get(target['name'])
        if not instance:
            return f"Alvo {target['name']} não encontrado"

        port = instance['port']
        zap = ZAPv2(apikey='123456789', proxies={'http': f'http://localhost:{port}', 'https': f'http://localhost:{port}'})
        progress = zap.automation.plan_progress(0)
        if progress['finished']:
            return f"Scan para {target['name']} concluído"
        else:
            return f"Scan para {target['name']} em andamento: {progress['progress']}% concluído"



@click.group()
def cli():
    pass

@click.command()
@click.option('--targets-file', required=True, help='Path to the targets file')
def start(targets_file):
    manager = ZAPManager(targets_file)
    manager.start_instances()
    logging.info("ZAP instances started")

@click.command()
def stop():
    with open('/tmp/zap_manager.pid', 'r') as f:
        pid = int(f.read().strip())
    os.kill(pid, 15)  # Envia o sinal TERM para o processo
    logging.info("All ZAP instances stopped and results collected")

@click.command()
@click.option('--targets-file', required=True, help='Path to the targets file')
def status(targets_file):
    manager = ZAPManager(targets_file)  # Dummy initialization to access methods
    progress = manager.get_scan_progress()
    print(progress)
    logging.info(progress)

cli.add_command(start)
cli.add_command(stop)
cli.add_command(status)

if __name__ == "__main__":
    cli()
