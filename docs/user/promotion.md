# Promote to IPAddress

Scanner is read-only enrichment by default — discovered hosts live in
their own `DiscoveredHost` model and never silently become
`ipam.IPAddress` records. The **Promote to IPAddress** action is the
explicit escape hatch when an operator decides a discovered host
should become a real IPAM record.

## Why this is opt-in

Auto-creating IPAM records from scan output is dangerous:

- A transient NAT or container that responded once becomes a permanent
  IPAM row that ages out as "missing"
- A misconfigured DHCP server bursting through the address space
  creates dozens of bogus IPAddresses
- A spoofing attacker decides what shows up in your source of truth

The Promote action puts a human in the loop and forces an explicit
permission check.

## Permission requirements

The promote view checks `request.user.has_perm("ipam.add_ipaddress")` —
**not** just scanner permissions. You can be a Scanner admin and still
get denied if you can't add IPAddresses in IPAM. This is intentional:
creating an IPAddress is an IPAM-side operation.

If you need to give an operator promote capability:

1. Grant the user (or their group) the **add_ipaddress** permission
   under **Admin > Permissions**
2. Restrict by object filter if needed (e.g., only allow promoting
   hosts in specific prefixes)

## The flow

1. Open the `DiscoveredHost` detail page (Apps > Scanner > Discovered
   Hosts > _row_)
2. Click **Promote to IPAddress** in the actions menu
3. The form pre-fills:
   - **Address**: from `DiscoveredHost.ip_address`
   - **DNS Name**: from `DiscoveredHost.hostname` (if present)
4. You fill in:
   - **Namespace** (typically "Global")
   - **Parent Prefix** (auto-suggested from the scan's target prefixes)
   - **Status** (typically "Active")
   - **Tenant** (optional)
   - **Tags** (optional)
5. Submit. The view:
   - Creates the `ipam.IPAddress`
   - Sets `DiscoveredHost.linked_ipaddress` to the new record
   - Redirects you to the new IPAddress detail page

## What happens to the DiscoveredHost

Promotion doesn't delete the `DiscoveredHost`. It links to the new
IPAddress so future scans of the same IP will:

- Match the existing IPAddress via the `linked_ipaddress` FK
- Show up in the **Scanner** panel on that IPAddress's detail page
- Get scan-summary data on the IPAddress's history

## What promotion does NOT do

- It doesn't create a `dcim.Device` — discovered devices have far more
  shape (device type, role, location) than scan output captures.
  Operators create Devices manually, then `DiscoveredHost.linked_device`
  populates at the next scan via IP match against `Device.primary_ip4/6`.
- It doesn't carry forward open ports, OS guesses, or vulnerabilities
  to the new IPAddress — those stay attached to the scan row, where
  they belong as historical artifacts. The IPAddress detail page reads
  them back via the link.
- It doesn't write any of the discovered host's metadata into
  IPAddress custom fields by default. If you want that, write a signal
  handler (see [Extending](../dev/extending.md)).
