"""Enable all nautobot_scanner Jobs (Nautobot defaults new jobs to enabled=False)."""

from nautobot.extras.models import Job

jobs = Job.objects.filter(module_name="nautobot_scanner.jobs")
print(f"Found {jobs.count()} Scanner jobs.")
for job in jobs:
    if not job.enabled:
        job.enabled = True
        job.save()
        print(f"  Enabled: {job.name}")
    else:
        print(f"  Already enabled: {job.name}")
