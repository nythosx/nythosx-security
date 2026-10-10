from rich.console import Console

from .orchestrator import Orchestrator


console = Console()


def run_auto(url, min_severity="medium", credentials=None, skip_discovery=False,
             api_override=None, adapter_override=None, auto_baseline=False,
             job_id=None):
    import sys
    this = sys.modules[__name__]
    orc = Orchestrator(console=this.console)
    return orc.run_auto_compat(
        url=url,
        min_severity=min_severity,
        credentials=credentials,
        skip_discovery=skip_discovery,
        api_override=api_override,
        adapter_override=adapter_override,
        auto_baseline=auto_baseline,
        job_id=job_id,
    )
