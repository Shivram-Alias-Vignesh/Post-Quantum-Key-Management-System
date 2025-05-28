import requests
import time
from rich.console import Console
from rich.table import Table
from rich.live import Live

console = Console()
BASE_URL = "http://localhost:5000"

def get_slowloris_attack():
    return {
        'url': BASE_URL,
        'method': 'GET',
        'headers': {
            'X-ATTACK-TYPE': 'SLOWLORIS',
            'User-Agent': 'MALICIOUS-SLOWLORIS',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Keep-Alive': '900'
        },
        'timeout': 30
    }

def test_slowloris():
    console.print("\n[bold red]SLOWLORIS TEST[/bold red]")
    table = Table(title="Slowloris Attack Progress")
    table.add_column("Time (s)")
    table.add_column("Status")
    table.add_column("Protocol State")
    
    activated = False
    activation_time = None
    start_time = time.time()
    
    with Live(table, refresh_per_second=4) as live:
        while time.time() - start_time < 120:  # 2 minute test
            attack = get_slowloris_attack()
            try:
                response = requests.get(
                    attack['url'],
                    headers=attack['headers'],
                    timeout=attack['timeout']
                )
                status = response.status_code
            except:
                status = "FAILED"
            
            # Check if protocol activated
            check = requests.get(BASE_URL, timeout=1)
            activated = "Quantum Escape Protocol" in check.text
            
            table.add_row(
                f"{time.time()-start_time:.1f}",
                str(status),
                "[blink red]ACTIVATED[/blink red]" if activated else "normal"
            )
            
            if activated:
                activation_time = time.time() - start_time
                break
                
            time.sleep(5)
    
    console.print("\n[bold]RESULTS:[/bold]")
    if activated:
        console.print(f"[green]SUCCESS[/green]: Protocol activated after {activation_time:.1f} seconds")
    else:
        console.print("[red]FAILURE[/red]: Slowloris attack not detected")

if __name__ == "__main__":
    test_slowloris()