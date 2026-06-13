import json
import glob
import pandas as pd

def collect_alerts():
    # Collecte tous les fichiers d'alertes
    files = glob.glob('/var/ossec/logs/alerts/2026/**/*.json', recursive=True)
    files.append('/var/ossec/logs/alerts/alerts.json')
    
    print(f"📁 {len(files)} fichiers trouvés")
    
    alerts = []
    for alerts_file in files:
        try:
            with open(alerts_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    try:
                        alert = json.loads(line.strip())
                        
                        rule_id = alert.get('rule', {}).get('id', 0)
                        rule_level = alert.get('rule', {}).get('level', 0)
                        rule_desc = alert.get('rule', {}).get('description', '')
                        firedtimes = alert.get('rule', {}).get('firedtimes', 0)
                        agent_name = alert.get('agent', {}).get('name', '')
                        
                        src_ip = (
                            alert.get('data', {}).get('srcip', '') or
                            alert.get('data', {}).get('win', {}).get('eventdata', {}).get('ipAddress', '') or
                            ''
                        )
                        
                        event_id = alert.get('data', {}).get('win', {}).get('system', {}).get('eventID', 0)
                        process_name = alert.get('data', {}).get('win', {}).get('eventdata', {}).get('image', '')
                        command_line = alert.get('data', {}).get('win', {}).get('eventdata', {}).get('commandLine', '')
                        
                        # Label automatique
                        label = 0
                        attack_rules = [
                            '60122', '60204',
                            '60144', '60145', '60146','60109',
                            '60170', '60171', '60172',
                            '92031', '92033','92039',
                            '92213', '92200', '92201',
                            '92302',
                            '92657',
                            '40111', '40112',
                            '86601'
                     
                        ]
                        if int(rule_level) >= 10:
                            label = 1
                        if str(rule_id) in attack_rules:
                            label = 1
                        if 'brute' in rule_desc.lower() or 'attack' in rule_desc.lower():
                            label = 1
                        if 'hacker' in command_line.lower():
                            label = 1
                        if 'suricata' in rule_desc.lower() or 'nmap' in rule_desc.lower():
                            label = 1
                        if 'anonymous' in rule_desc.lower() or 'ntlm' in rule_desc.lower():
                            label = 1 
 
                       


                        alerts.append({
                            'timestamp': alert.get('timestamp', ''),
                            'rule_id': rule_id,
                            'rule_level': rule_level,
                            'rule_description': rule_desc,
                            'firedtimes': firedtimes,
                            'src_ip': src_ip,
                            'agent_name': agent_name,
                            'event_id': event_id,
                            'process_name': process_name,
                            'command_line': command_line,
                            'label': label
                        })
                    except:
    
                      continue
        except:
            continue

    df = pd.DataFrame(alerts)
    df.to_csv('alerts.csv', index=False)
    print(f"✅ {len(df)} alertes collectées dans alerts.csv")
    print(f"Normal: {len(df[df['label']==0])} | Attaque: {len(df[df['label']==1])}")
    return df

if __name__ == '__main__':
    df = collect_alerts()
    print(df[['rule_id', 'rule_level', 'rule_description', 'label']].head(20))
