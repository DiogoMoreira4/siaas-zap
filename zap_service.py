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
import sys
import requests

logging.basicConfig(filename='zap_manager.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

USER = os.getenv("USER") or os.getenv("LOGNAME")
HOME_DIR = os.path.expanduser("~")
SIAAS_ZAP_DIR = os.path.dirname(os.path.abspath(__file__))

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
    required_fields = ['name', 'url']
    for section in config.sections():
        items = dict(config.items(section))
        if not all(field in items for field in required_fields):
            logging.error(f"Error: Target '{section}' doesn't contain the required fields to be analized. Required fields: {', '.join(required_fields)}.")
            sys.exit(1)
        auth_required_fields = ['username', 'password', 'loginpage']
        items['has_auth'] = all(field in items for field in auth_required_fields)
        targets[section] = items
    return targets


def start_zap_instance(port, api_key, directory):
    
    if not os.path.exists(directory):
        os.makedirs(directory)
        # Set ownership and permissions
        shutil.chown(directory, user=USER, group=USER)
        os.chmod(directory, 0o755)
    command = f"{HOME_DIR}/zaproxy/ZAP_2.15.0/zap.sh -daemon -addoninstallall -port {port} -dir {directory} -config api.key={api_key}"
    process = subprocess.Popen(command.split())
    return process


def modify_automation_plan(template_with_auth_path, template_without_auth_path, output_path, target, automationConfigs):
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
            dados_yaml['jobs'][2]['parameters']['maxDuration'] = automationConfigs['spider_max_duration']
            dados_yaml['jobs'][2]['parameters']['maxDepth'] = automationConfigs['spider_max_depth']
            dados_yaml['jobs'][2]['parameters']['maxChildren'] = automationConfigs['spider_max_children']
            #spiderAjax
            dados_yaml['jobs'][3]['parameters']['context'] = target['name']
            dados_yaml['jobs'][3]['parameters']['user'] = target['username']
            dados_yaml['jobs'][3]['parameters']['maxDuration'] = automationConfigs['ajax_spider_max_duration']
            dados_yaml['jobs'][3]['parameters']['maxCrawlDepth'] = automationConfigs['ajax_spider_max_depth']
            dados_yaml['jobs'][3]['parameters']['numberOfBrowsers'] = automationConfigs['ajax_spider_number_of_browsers']
            #delay
            #passiveScan-wait
            #activeScan
            dados_yaml['jobs'][6]['parameters']['context'] = target['name']
            dados_yaml['jobs'][6]['parameters']['user'] = target['username']
            dados_yaml['jobs'][6]['parameters']['maxRuleDurationInMins'] = automationConfigs['active_scan_max_rule_duration']
            dados_yaml['jobs'][6]['parameters']['maxScanDurationInMins'] = automationConfigs['active_scan_max_scan_duration']
            dados_yaml['jobs'][6]['parameters']['maxAlertsPerRule'] = automationConfigs['active_scan_max_alerts_per_rule']
            dados_yaml['jobs'][6]['policyDefinition']['defaultStrength'] = automationConfigs['active_scan_default_strength']
            dados_yaml['jobs'][6]['policyDefinition']['defaultThreshold'] = automationConfigs['active_scan_default_threshold']
            #report
            dados_yaml['jobs'][7]['parameters']['reportFile'] = target['name']
            dados_yaml['jobs'][7]['parameters']['reportDir'] =  SIAAS_ZAP_DIR+"/reports"  
        
    else:
        if 'env' in dados_yaml and 'contexts' in dados_yaml['env']:
            for aux in dados_yaml['env']['contexts']:
                aux['name'] = target['name']
                aux['urls'] = [target['url']]
                aux['includePaths'] = [target['url']+ '.*'] 
        if 'jobs' in dados_yaml:
            #spider
            dados_yaml['jobs'][1]['parameters']['context'] = target['name']
            dados_yaml['jobs'][1]['parameters']['maxDuration'] = automationConfigs['spider_max_duration']
            dados_yaml['jobs'][1]['parameters']['maxDepth'] = automationConfigs['spider_max_depth']
            dados_yaml['jobs'][1]['parameters']['maxChildren'] = automationConfigs['spider_max_children']
            #spiderAjax
            dados_yaml['jobs'][2]['parameters']['context'] = target['name']
            dados_yaml['jobs'][2]['parameters']['maxDuration'] = automationConfigs['ajax_spider_max_duration']
            dados_yaml['jobs'][2]['parameters']['maxCrawlDepth'] = automationConfigs['ajax_spider_max_depth']
            dados_yaml['jobs'][2]['parameters']['numberOfBrowsers'] = automationConfigs['ajax_spider_number_of_browsers']
            #passiveScan-wait
            #activeScan
            dados_yaml['jobs'][4]['parameters']['context'] = target['name']
            dados_yaml['jobs'][4]['parameters']['maxRuleDurationInMins'] = automationConfigs['active_scan_max_rule_duration']
            dados_yaml['jobs'][4]['parameters']['maxScanDurationInMins'] = automationConfigs['active_scan_max_scan_duration']
            dados_yaml['jobs'][4]['parameters']['maxAlertsPerRule'] = automationConfigs['active_scan_max_alerts_per_rule']
            dados_yaml['jobs'][4]['policyDefinition']['defaultStrength'] = automationConfigs['active_scan_default_strength']
            dados_yaml['jobs'][4]['policyDefinition']['defaultThreshold'] = automationConfigs['active_scan_default_threshold']
            #report
            dados_yaml['jobs'][5]['parameters']['reportFile'] = target['name'] + "_without_auth"  
            dados_yaml['jobs'][5]['parameters']['reportDir'] =  SIAAS_ZAP_DIR+"/reports"  
                
    with open(output_path, 'w') as file:
        yaml.safe_dump(dados_yaml, file)


def run_scan(zap, plan_path, session_name):
    zap.core.new_session(name=session_name, overwrite=True)
    zap.automation.run_plan(plan_path)
    
    
def wait_for_zap_start(port, api_key, timeout=180):
    zap = ZAPv2(apikey=api_key, proxies={'http': f'http://localhost:{port}', 'https': f'http://localhost:{port}'})
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
    
    
def get_scan_progress(zap, target):
        
    if zap.ascan.status(0) == "does_not_exist":    
        logging.info(f"Crawling the target {target}...")
    else:
        progress = zap.ascan.status(0)   
        logging.info(f"Active Scan to {target} in progress: {progress}%")


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




class ZAPManager:
    def __init__(self, targets_file):
        try:
            config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'conf', 'config.ini')
            self.targets_file = targets_file
            self.base_dir = os.path.join(SIAAS_ZAP_DIR, "instances", "instance")
            self.api_uri = read_config(config_file, 'APIConfig', 'api_uri')
            self.api_user = read_config(config_file, 'APIConfig', 'api_user')
            self.api_password = read_config(config_file, 'APIConfig', 'api_pwd')
            self.api_ssl_ignore = read_config(config_file, 'APIConfig', 'api_ssl_ignore_verify')
            self.api_ssl_ca_bundle = read_config(config_file, 'APIConfig', 'api_ssl_ca_bundle')
            self.targets = read_targets(targets_file)
            self.zap_instances = {}
            self.current_target = None
            self.pid_file = "/tmp/zap_manager.pid"
            self.zap_config = siaas_aux.get_request_to_server(
                "https://127.0.0.1/api/siaas-server/siaas-zap/config",
                ignore_ssl=True,
                ca_bundle=self.api_ssl_ca_bundle,
                api_user=self.api_user,
                api_pwd=self.api_password
            )
            self._create_pid_file()
        except Exception as e:
            logging.error(f"Error during initialization: {str(e)}")
            raise

    def _create_pid_file(self):
        try:
            with open(self.pid_file, 'w') as f:
                f.write(str(os.getpid()))
        except PermissionError:
            alternate_pid_file = os.path.expanduser('~/zap_manager.pid')
            try:
                with open(alternate_pid_file, 'w') as f:
                    f.write(str(os.getpid()))
                self.pid_file = alternate_pid_file
            except Exception as e:
                logging.error(f"Failed to create PID file: {str(e)}")
                raise

    def _remove_pid_file(self):
        if os.path.exists(self.pid_file):
            try:
                os.remove(self.pid_file)
            except Exception as e:
                logging.error(f"Failed to remove PID file: {str(e)}")

    def start_instances(self):
        logging.info(f"Targets to scan: {self.targets}")
        try:
            target_keys = list(self.targets.keys())
            for idx, target_key in enumerate(target_keys):
                target = self.targets[target_key]
                self.current_target = target  
                try:
                    port = int(self.zap_config['ZAPConfig']['base_port']) + idx
                    directory = f"{self.base_dir}{idx}"
                    process = start_zap_instance(port, self.zap_config['ZAPConfig']['api_key'], directory)
                    self.zap_instances[target['name']] = {"port": port, "directory": directory}
                    logging.info(f"Instance {idx} created to scan {target['name']}")
                  
                    zap = wait_for_zap_start(port, self.zap_config['ZAPConfig']['api_key'])
                    logging.info(f"Connected to the instance {idx}")
                    
                    plan_path = f"{directory}/automation_plan.yaml"
                    pathtoplans = os.path.dirname(os.path.abspath(__file__))
                    modify_automation_plan(
                        f"{pathtoplans}/PlanWithAuth.yaml",
                        f"{pathtoplans}/PlanWithoutAuth.yaml",
                        plan_path,
                        target,
                        self.zap_config['AutomationPlansConfig']
                    )
                    logging.info("Automation Plan modified and ready!")
                    
                    session_name = f"session_{target['name']}_{port}"
                    run_scan(zap, plan_path, session_name)
                    
                    while not is_scan_complete(zap):
                        get_scan_progress(zap, target['name'])
                        time.sleep(300)  
                    
                    results = collect_results(zap, target['name'])
                    siaas_aux.post_request_to_server(
                        f"{self.api_uri}/siaas-server/siaas-zap/results",
                        results,
                        ignore_ssl=True,
                        ca_bundle=self.api_ssl_ca_bundle,
                        api_user=self.api_user,
                        api_pwd=self.api_password
                    )
                    logging.info(f"HTTPS request with scan results of {target['name']} sent to the server API!")
                except Exception as e:
                    logging.error(f"Error during scanning {target['name']}: {str(e)}")
                finally:
                    if target['name'] in self.zap_instances:
                        os.kill(process.pid, signal.SIGTERM)
                        logging.info(f"Instance from port {port} stopped!")
                        del self.zap_instances[target['name']]

                    if os.path.exists(directory):
                    try:
                        shutil.rmtree(directory)
                        logging.info(f"Session data for instance {idx} ({target['name']}) removed successfully.")
                    except Exception as e:
                        logging.error(f"Failed to remove session data for instance {idx}: {str(e)}", exc_info=True)
                    
            logging.info("All targets were scanned. Finishing the service.")
            self.stop_service()
        except Exception as e:
            logging.error(f"Unexpected error: {str(e)}")
        finally:
            self._remove_pid_file()

    def stop_service(self):
        try:
            with open(self.pid_file, 'r') as f:
                pid = int(f.read().strip())
            os.kill(pid, 15)  # Envia o sinal TERM para o processo
            logging.info("All ZAP instances stopped and results collected.")
        except Exception as e:
            logging.error(f"Error while stopping the service: {str(e)}")



@click.group()
def cli():
    pass

@click.command()
@click.option('--targets-file', required=True, help='Path to the targets file')
def start(targets_file):
    manager = ZAPManager(targets_file)
    logging.info("Starting the ZAP service...")
    manager.start_instances()

@click.command()
def stop():
    with open('/tmp/zap_manager.pid', 'r') as f:
        pid = int(f.read().strip())
    os.kill(pid, 15)  # Envia o sinal TERM para o processo
    logging.info("All ZAP instances stopped and results collected")


cli.add_command(start)
cli.add_command(stop)

if __name__ == "__main__":
    cli()
