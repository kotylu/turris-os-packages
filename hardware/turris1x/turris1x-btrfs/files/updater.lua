--[[
This file is part of package turris1x-btrfs. Don't edit it.
This ensures that if we are running on BTRFS root that turris1x-btrfs is installed.
]]
-- TODO nonroot
local is_btrfs = os.execute("grep -q '^/dev/mmcblk0p2 / btrfs' /proc/mounts") == 0

if is_btrfs then
	Install("turris1x-btrfs", { critical = true })
end
