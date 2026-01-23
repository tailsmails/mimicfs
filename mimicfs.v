// v -prod -gc boehm -prealloc -skip-unused -d no_backtrace -d no_debug -cc clang -cflags "-O3 -flto -fPIE -fstack-protector-all -fstack-clash-protection -D_FORTIFY_SOURCE=3 -fno-ident -fno-common -fwrapv -ftrivial-auto-var-init=zero -fvisibility=hidden -Wformat -Wformat-security -Werror=format-security" -ldflags "-pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code -Wl,--gc-sections -Wl,--icf=all -Wl,--build-id=none" mimicfs.v -o mimicfs && strip --strip-all --remove-section=.comment --remove-section=.note --remove-section=.gnu.version mimicfs

import os
import time
import term
import math
import term.ui as tui
import crypto.sha256

fn send_notification(title string, message string) {
	os.execute("su -lp 2000 -c \"cmd notification post -S bigtext -t '$title' 'Security_Monitor' '$message'\"")
}

fn get_ppid(pid int) int {
	lines := os.read_lines('/proc/$pid/status') or { return 0 }
	for line in lines {
		if line.starts_with('PPid:') {
			parts := line.split(':')
			if parts.len > 1 {
				return parts[1].trim_space().int()
			}
		}
	}
	return 0
}

fn get_gps_interrupt_sum() i64 {
	mut total := i64(0)
	lines := os.read_lines('/proc/interrupts') or { return 0 }
	for line in lines {
		if line.contains('gps') {
			fields := line.fields()
			for i in 1 .. fields.len {
				val := fields[i].i64()
				if val > 0 { total += val }
			}
		}
	}
	return total
}

fn disable_sim_toolkit() {
	pkgs := ['com.android.stk', 'com.google.android.stk', 'com.samsung.android.stk']
	for pkg in pkgs {
		os.execute("su -c \"pm disable-user --user 0 $pkg\"")
	}
}

fn get_time_str() string {
	t := time.now()
	return '${t.hour:02}:${t.minute:02}:${t.second:02}'
}

fn despy() {
	println('${term.cyan('DeSpy 1.3')}')

	if os.args.len > 1 && os.args[1] == 'r' {
		os.execute("su -c \"echo 'musb-hdrc' > /config/usb_gadget/g1/UDC\"")
		os.execute("setprop sys.usb.config mtp,adb")
		os.execute("setprop sys.usb.state mtp,adb")
		println("${term.green('✔')} [${get_time_str()}] USB Port Restored. Monitoring Stopped.")
		return
	}

	os.execute("su -c \"echo '' > /config/usb_gadget/g1/UDC\"")
	os.execute("setprop sys.usb.config none")
	os.execute("setprop sys.usb.state none")

	disable_sim_toolkit()

	mut camera_paths := []string{}
	mut mic_status_paths := []string{}
	camera_keywords := ['vcam', 'camera', 'vfe', 'avdd', 'ov', 'imx']
	reg_base := '/sys/class/regulator'

	if os.exists(reg_base) {
		reg_dirs := os.ls(reg_base) or { []string{} }
		for dir in reg_dirs {
			name_file := reg_base + '/' + dir + '/name'
			if os.exists(name_file) {
				name := os.read_file(name_file) or { '' }.to_lower()
				for kw in camera_keywords {
					if name.contains(kw) {
						u_path := reg_base + '/' + dir + '/num_users'
						if os.exists(u_path) { camera_paths << u_path; break }
					}
				}
			}
		}
	}

	asound_base := '/proc/asound'
	if os.exists(asound_base) {
		cards := os.ls(asound_base) or { []string{} }
		for card in cards {
			if card.starts_with('card') {
				card_path := asound_base + '/' + card
				pcms := os.ls(card_path) or { []string{} }
				for pcm in pcms {
					if pcm.ends_with('c') {
						sub_dirs := os.ls(card_path + '/' + pcm) or { []string{} }
						for sub in sub_dirs {
							if sub.starts_with('sub') {
								status_file := card_path + '/' + pcm + '/' + sub + '/status'
								if os.exists(status_file) { mic_status_paths << status_file }
							}
						}
					}
				}
			}
		}
	}

	println('${term.yellow('⚠')} [${get_time_str()}] DeSpy Active: USB Port KILLED & Monitoring Started.')

	mut last_cam_state := false
	mut last_mic_state := false
	mut last_gps_state := false
	mut last_gps_sum := get_gps_interrupt_sum()
	mut gps_stagnant_count := 0
	my_pid := os.getpid()

	for {
		pids := os.ls('/proc') or { []string{} }
		mut rild_pids := []int{}
		ts := get_time_str()

		for pid_s in pids {
			if !pid_s.is_int() { continue }
			pid_i := pid_s.int()
			if pid_i == my_pid { continue }

			cmdline := os.read_file('/proc/$pid_s/cmdline') or { '' }
			if cmdline.contains('rild') || cmdline.contains('radio') || cmdline.contains('com.android.phone') {
				rild_pids << pid_i
			}
		}

		for pid_s in pids {
			if !pid_s.is_int() { continue }
			pid_i := pid_s.int()
			if pid_i <= 1000 || pid_i == my_pid { continue }

			stat_path := '/proc/$pid_s/status'
			if os.exists(stat_path) {
				uid_data := os.read_file(stat_path) or { '' }
				
				ppid := get_ppid(pid_i)
				if ppid in rild_pids {
					exe_path := os.execute('readlink /proc/$pid_s/exe').output.trim_space()
					if exe_path.ends_with('/sh') || 
					   exe_path.ends_with('/bash') || 
					   exe_path.contains('curl') || 
					   exe_path.contains('wget') || 
					   exe_path.contains('busybox') ||
					   exe_path.contains('/data/local/tmp') {
						
						println('${term.red('☠')} [$ts] CRITICAL: Baseband Exploit Detected! RIL spawned: $exe_path')
						os.execute('kill -9 $pid_i')
						os.execute('kill -9 $ppid')
						send_notification('BASEBAND ATTACK', 'RIL process killed due to exploit attempt.')
					}
				}

				if uid_data.contains('Uid:\t0') || uid_data.contains('Uid: 0') {
					mut is_vulnerable := false
					maps_path := '/proc/$pid_s/maps'
					if os.exists(maps_path) {
						maps_lines := os.read_lines(maps_path) or { []string{} }
						for line in maps_lines {
							if line.contains('rwxp') {
								is_vulnerable = true
								break
							}
						}
					}

					exe_res := os.execute('readlink /proc/$pid_s/exe')
					exe_path := exe_res.output.trim_space()
					
					if exe_path.len > 0 {
						is_trusted := exe_path.starts_with('/system/') || 
									  exe_path.starts_with('/vendor/') || 
									  exe_path.starts_with('/apex/') ||
									  exe_path.starts_with('/odm/') ||
									  exe_path.starts_with('/product/') ||
									  exe_path.starts_with('/system_ext/') ||
									  exe_path.starts_with('/data/app/') ||
									  exe_path.starts_with('/data/adb/') ||
									  exe_path.starts_with('/debug_ramdisk/') ||
									  exe_path.starts_with('/dev/') || 
									  exe_path.starts_with('/data/data/com.termux/files/')

						if !is_trusted || (is_vulnerable && !is_trusted) {
							os.execute('kill -9 $pid_i')
							reason := if is_vulnerable { 'Memory Integrity Violation' } else { 'Untrusted Root' }
							msg := '$reason: $exe_path (PID: $pid_i)'
							println('${term.red('✘')} [$ts] $msg')
							send_notification('Security Alert', msg)
						}
					}
				}
			}
		}

		mut cam_active := false
		for cp in camera_paths {
			if os.read_file(cp) or { '0' }.trim_space().int() > 0 { cam_active = true; break }
		}

		mut mic_active := false
		for mp in mic_status_paths {
			if (os.read_file(mp) or { '' }).contains('RUNNING') { mic_active = true; break }
		}

		cur_gps_sum := get_gps_interrupt_sum()
		mut gps_active := false
		if cur_gps_sum > last_gps_sum {
			gps_active = true
			gps_stagnant_count = 0
			last_gps_sum = cur_gps_sum
		} else {
			gps_stagnant_count++
			if gps_stagnant_count < 3 { gps_active = last_gps_state }
		}

		if cam_active != last_cam_state {
			if cam_active { 
				send_notification('Alert', 'Camera sensor active.')
				println('${term.yellow('⚠')} [$ts] Camera active.') 
			}
			last_cam_state = cam_active
		}
		if mic_active != last_mic_state {
			if mic_active { 
				send_notification('Alert', 'Microphone sensor active.')
				println('${term.yellow('⚠')} [$ts] Microphone active.') 
			}
			last_mic_state = mic_active
		}
		if gps_active != last_gps_state {
			if gps_active { 
				send_notification('Alert', 'GPS hardware active.')
				println('${term.yellow('⚠')} [$ts] GPS activity.') 
			}
			last_gps_state = gps_active
		}

		time.sleep(3000 * time.millisecond)
	}
}

fn manage_snapshot_protection(enable bool) {
	targets := [
		'/data/system_ce/0/snapshots',
		'/data/system_ce/0/usagestats',
		'/data/system/dropbox',
		'/data/tombstones',
		'/data/anr',
	]

	for target in targets {
		if !exists(target) {
			continue
		}

		mounts := os.execute('mount').output
		is_mounted := mounts.contains(target)

		if enable {
			if is_mounted {
				continue
			}

			raw := os.execute('ls -dZ ${target}').output
			mut ctx := raw.split(' ')[0].trim_space()
			if ctx == '?' || ctx.len < 5 {
				ctx = 'u:object_r:system_data_file:s0'
			}

			cmd := 'mount -t tmpfs -o size=64M,mode=0700,uid=1000,gid=1000,context=${ctx} tmpfs ${target}'
			mut res := os.execute(cmd)

			if res.exit_code != 0 {
				cmd_simple := 'mount -t tmpfs -o size=64M,mode=0700,uid=1000,gid=1000 tmpfs ${target}'
				res = os.execute(cmd_simple)
			}

			if res.exit_code == 0 {
				run('restorecon -R ${target}')
				if target.contains('usagestats') {
					run('mkdir -p ${target}/daily ${target}/weekly ${target}/monthly ${target}/yearly')
					run('chown -R 1000:1000 ${target}')
					run('restorecon -R ${target}')
				}
				println('${term.green('✔')} Secured: ${target}')
			} else {
				println('${term.yellow('⚠')} Failed to secure ${target}')
			}
		} else {
			if !is_mounted {
				continue
			}
			wipe_ram(target)
			run('umount -l ${target}')
		}
	}

	if !enable {
		run('echo 3 > /proc/sys/vm/drop_caches')
	}
}

fn trigger_vibrate(duration_ms int) {
	uid := os.execute('stat -c %u /data/data/com.termux').output.trim_space()
	os.execute('su ${uid} -c "PATH=/data/data/com.termux/files/usr/bin:\$PATH LD_LIBRARY_PATH=/data/data/com.termux/files/usr/lib termux-vibrate -d ${duration_ms}"')
}

fn get_mag_value_from_root() f64 {
	uid := os.execute('stat -c %u /data/data/com.termux').output.trim_space()
	res := os.execute('su ${uid} -c "export PATH=/data/data/com.termux/files/usr/bin; export TMPDIR=/data/data/com.termux/files/usr/tmp; timeout 2s termux-sensor -s \'MAGNETOMETER\' -n 1"')
	if res.exit_code != 0 || !res.output.contains('"values":') {
		return -1.0
	}
	raw := res.output
	vals_str := raw.all_after('"values": [').all_before(']')
	parts := vals_str.split(',')
	if parts.len >= 3 {
		x := parts[0].trim_space().f64()
		y := parts[1].trim_space().f64()
		z := parts[2].trim_space().f64()
		return math.sqrt((x * x) + (y * y) + (z * z))
	}
	return -1.0
}

fn info(msg string) {
	println('${term.blue('ℹ')} ${msg}')
}

fn success(msg string) {
	println('${term.green('✔')} ${msg}')
}

fn warn(msg string) {
	println('${term.yellow('⚠')} ${msg}')
}

fn error2(msg string) {
	println('${term.red('✘')} ${msg}')
}

fn fatal(msg string) {
	println('${term.bg_red(term.white(' FATAL '))} ${msg}')
	exit(1)
}

struct TrackedApp {
	pkg_name string
	pw       string
mut:
	timer int
	sync  int
}

fn exists(path string) bool {
	res := os.execute('test -e ${path}')
	return res.exit_code == 0
}

fn kill_disk_swap() {
	swaps := os.read_file('/proc/swaps') or { return }
	lines := swaps.split_into_lines()

	for i in 1 .. lines.len {
		line := lines[i]
		if line.len < 5 {
			continue
		}
		parts := line.fields()
		if parts.len < 1 {
			continue
		}
		path := parts[0]
		if path.contains('/data/') || path.contains('/mnt/expand/') {
			info('Dangerous Disk-Swap detected: ${path}. Disabling ...')
			run('swapoff ${path}')
			size_kb := parts[2].int()
			if size_kb > 0 {
				info('Wiping swap file on disk (${size_kb} KB) for security...')
				run('dd if=/dev/urandom of=${path} bs=1K count=${size_kb} conv=fsync')
				run('rm -f ${path}')
			}
			success('Disk-swap eliminated.')
		}
	}
}

@[inline]
fn run(cmd string) {
	os.system('${cmd} 2>/dev/null')
}

fn get_meta(dp string) (string, string) {
	u := os.execute('stat -c %u ${dp} 2>/dev/null').output.trim_space()
	c_raw := os.execute('ls -dZ ${dp} 2>/dev/null').output
	c := c_raw.split(' ')[0]
	if c == '' || c == '?' {
		return u, 'u:object_r:app_data_file:s0'
	}
	return u, c
}

fn kill_app(pkg string) {
	run('am force-stop ${pkg}')
	run('pm disable-user --user 0 ${pkg}')
	u := os.execute('stat -c %u /data/data/${pkg} 2>/dev/null').output.trim_space()
	if _likely_(u.len > 0) {
		run('pkill -9 -u ${u}')
	}
	time.sleep(1400 * time.millisecond)
}

fn wipe_ram(path string) {
	run('dd if=/dev/urandom of=${path}/wipe_rand bs=1M conv=fsync')
	run('dd if=/dev/zero of=${path}/wipe_zero bs=1M conv=fsync')
	run('rm ${path}/wipe_rand ${path}/wipe_zero')
}

fn start_app_core(pkg string, pw string) int {
	for b in pkg.bytes() {
		if !((b >= 97 && b <= 122) || (b >= 65 && b <= 90) || (b >= 48 && b <= 57) || b == 46 || b == 95) {
			return 1
		}
	}

	kill_disk_swap()

	if !os.exists('/data/data/${pkg}') {
		return 1
	}

	u, c := get_meta('/data/data/${pkg}')
	
	safe_pkg := "'${pkg}'"
	pid := pkg.replace('.', '_')
	
	dp := '/data/data/${pkg}'
	safe_dp := "'${dp}'"
	
	rp := '/mnt/ram_${pid}'
	safe_rp := "'${rp}'"
	
	vf := '/data/local/tmp/${pkg}.enc'
	safe_vf := "'${vf}'"
	
	pedp := '/data/media/0/Android/data/${pkg}'
	safe_pedp := "'${pedp}'"
	
	vedp := '/storage/emulated/0/Android/data/${pkg}'
	safe_vedp := "'${vedp}'"
	
	redp := '/mnt/runtime/write/emulated/0/Android/data/${pkg}'
	safe_redp := "'${redp}'"
	
	erp := '/mnt/ext_${pid}'
	safe_erp := "'${erp}'"
	
	evf := '/data/local/tmp/${pkg}.ext.enc'
	safe_evf := "'${evf}'"

	kill_app(pkg)
	run('umount -l ${safe_dp}')
	run('mkdir -p ${safe_rp}')

	mut needed_storage := 1024
	mut needed_data := 1024

	if os.exists(evf) && os.exists(vf) {
		res := os.execute('du -sm ${safe_evf} 2>/dev/null')
		res_two := os.execute('du -sm ${safe_vf} 2>/dev/null')

		if res.exit_code == 0 {
			parts := res.output.split('\t')
			if parts.len > 0 {
				val := parts[0].int()
				if val > 0 {
					needed_storage = val * 5
				}
			}
		}

		if res_two.exit_code == 0 {
			parts := res_two.output.split('\t')
			if parts.len > 0 {
				val := parts[0].int()
				if val > 0 {
					needed_data = val * 5
				}
			}
		}
	}

	run('mount -t tmpfs -o size=${needed_data}M,mode=771 tmpfs ${safe_rp}')

	if os.exists(vf) {
		cmd_main := 'openssl enc -chacha20 -d -pbkdf2 -iter 200000 -md sha512 -pass stdin -in ${safe_vf} | zstd -d | tar -xp --numeric-owner -C ${safe_rp}'
		
		mut proc_main := os.new_process('/bin/sh')
		proc_main.set_args(['-c', cmd_main])
		proc_main.set_redirect_stdio()
		proc_main.run()
		proc_main.stdin_write(pw)
		os.fd_close(proc_main.stdio_fd[0])
		proc_main.wait()
		
		if proc_main.code != 0 {
			error2('WRONG PW OR BROKEN FILE')
			run('umount -f ${safe_rp}')
			run('umount -f ${safe_erp}')
			run('rm -rf ${safe_rp} ${safe_erp}')
			run('restorecon -R ${safe_dp}')
			run('pm enable ${safe_pkg}')
			return 1
		}
	} else {
		run('cp -a ${safe_dp}/. ${safe_rp}/')
	}

	run('chown -R ${u}:${u} ${safe_rp}')
	run('chcon -R ${c} ${safe_rp}')
	run('mount --bind ${safe_rp} ${safe_dp}')

	if os.exists(pedp) || os.exists(evf) {
		run('umount -l ${safe_pedp}')
		run('umount -l ${safe_vedp}')
		run('umount -l ${safe_redp}')
		run('mkdir -p ${safe_erp}')
		run('mount -t tmpfs -o size=${needed_storage}M,mode=770,uid=${u},gid=9997 tmpfs ${safe_erp}')

		if os.exists(evf) {
			cmd_ext := 'openssl enc -chacha20 -d -pbkdf2 -iter 200000 -md sha512 -pass stdin -in ${safe_evf} | zstd -d | tar -xp --numeric-owner -C ${safe_erp}'
			
			mut proc_ext := os.new_process('/bin/sh')
			proc_ext.set_args(['-c', cmd_ext])
			proc_ext.set_redirect_stdio()
			proc_ext.run()
			proc_ext.stdin_write(pw)
			os.fd_close(proc_ext.stdio_fd[0])
			proc_ext.wait()

			if proc_ext.code != 0 {
				error2('WRONG PW OR BROKEN FILE')
				run('umount -f ${safe_rp}')
				run('umount -f ${safe_erp}')
				run('rm -rf ${safe_rp} ${safe_erp}')
				run('restorecon -R ${safe_dp}')
				run('pm enable ${safe_pkg}')
				return 1
			}
		} else {
			run('cp -a ${safe_pedp}/. ${safe_erp}/')
		}

		run('chown -R ${u}:9997 ${safe_erp}')
		run('chcon -R u:object_r:media_rw_data_file:s0 ${safe_erp}')
		run('mount --bind ${safe_erp} ${safe_pedp}')
		run('mount --bind ${safe_erp} ${safe_vedp}')
		run('nsenter -t 1 -m mount --bind ${safe_erp} ${safe_pedp}')
		run('nsenter -t 1 -m mount --bind ${safe_erp} ${safe_vedp}')
		run('nsenter -t 1 -m mount --bind ${safe_erp} ${safe_redp}')
	}

	run('pm enable ${safe_pkg}')
	return 0
}

fn get_usage(path string) int {
	res := os.execute('df ${path}')
	if res.exit_code != 0 {
		return 0
	}
	parts := res.output.fields()
	for p in parts {
		if p.ends_with('%') {
			return p.replace('%', '').int()
		}
	}
	return 0
}

fn stop_app_core(pkg string, pw string) {
	pid := pkg.replace('.', '_')
	dp := '/data/data/${pkg}'
	rp := '/mnt/ram_${pid}'
	erp := '/mnt/ext_${pid}'

	mounts := os.execute('mount').output

	if mounts.contains(rp) {
		if get_usage(rp) >= 95 {
			println('Error: ${rp} usage is over 95%')
			return
		}
	}

	if mounts.contains(erp) {
		if get_usage(erp) >= 95 {
			println('Error: ${erp} usage is over 95%')
			return
		}
	}

	run('am force-stop ${pkg}')
	kill_app(pkg)
	
	os.setenv('V_PW', pw, true)
	if mounts.contains(rp) {
		run('tar -cp --numeric-owner -C ${rp} . | zstd | openssl enc -chacha20 -pbkdf2 -iter 200000 -md sha512 -salt -pass env:V_PW -out /data/local/tmp/${pkg}.enc')
	}
	if mounts.contains(erp) {
		run('tar -cp --numeric-owner -C ${erp} . | zstd | openssl enc -chacha20 -pbkdf2 -iter 200000 -md sha512 -salt -pass env:V_PW -out /data/local/tmp/${pkg}.ext.enc')
	}
	if exists(rp) {
		wipe_ram(rp)
	}
	if exists(erp) {
		wipe_ram(erp)
	}
	os.unsetenv('V_PW')
	paths_to_unmount := [dp, '/data/media/0/Android/data/${pkg}',
		'/storage/emulated/0/Android/data/${pkg}', '/mnt/runtime/write/emulated/0/Android/data/${pkg}']
	for path in paths_to_unmount {
		run('umount -f ${path}')
		run('nsenter -t 1 -m umount -f ${path}')
	}
	run('umount -f ${rp}')
	run('umount -f ${erp}')
	run('rm -rf ${rp} ${erp}')
	run('restorecon -R ${dp}')
	run('pm enable ${pkg}')
	run('echo 3 > /proc/sys/vm/drop_caches')
	run('sm fstrim')
}

fn stop_nokill_core(pkg string, pw string) {
	pid := pkg.replace('.', '_')
	rp := '/mnt/ram_${pid}'
	erp := '/mnt/ext_${pid}'
	mounts := os.execute('mount').output
	os.setenv('V_PW', pw, true)
	if mounts.contains(rp) {
		run('tar -cp --numeric-owner -C ${rp} . | zstd | openssl enc -chacha20 -pbkdf2 -iter 200000 -md sha512 -salt -pass env:V_PW -out /data/local/tmp/${pkg}.enc')
	}
	if mounts.contains(erp) {
		run('tar -cp --numeric-owner -C ${erp} . | zstd | openssl enc -chacha20 -pbkdf2 -iter 200000 -md sha512 -salt -pass env:V_PW -out /data/local/tmp/${pkg}.ext.enc')
	}
	if exists(rp) {
		wipe_ram(rp)
	}
	if exists(erp) {
		wipe_ram(erp)
	}
	os.unsetenv('V_PW')
}

fn stop_nosave_core(pkg string) {
	pid := pkg.replace('.', '_')
	dp := '/data/data/${pkg}'
	rp := '/mnt/ram_${pid}'
	erp := '/mnt/ext_${pid}'
	run('am force-stop ${pkg}')
	kill_app(pkg)
	if exists(rp) {
		wipe_ram(rp)
	}
	if exists(erp) {
		wipe_ram(erp)
	}
	paths_to_unmount := [dp, '/data/media/0/Android/data/${pkg}',
		'/storage/emulated/0/Android/data/${pkg}', '/mnt/runtime/write/emulated/0/Android/data/${pkg}']
	for path in paths_to_unmount {
		run('umount -f ${path}')
		run('nsenter -t 1 -m umount -f ${path}')
	}
	run('umount -f ${rp}')
	run('umount -f ${erp}')
	run('rm -rf ${rp} ${erp}')
	run('restorecon -R ${dp}')
	run('pm enable ${pkg}')
	run('echo 3 > /proc/sys/vm/drop_caches')
	run('sm fstrim')
}

fn purge_all() {
	manage_snapshot_protection(false)
	mounts := os.execute('mount').output
	for line in mounts.split_into_lines() {
		if line.contains('/mnt/ram_') || line.contains('/mnt/ext_') {
			target := line.split(' ')[2]
			prefix := if target.contains('/mnt/ram_') { '/mnt/ram_' } else { '/mnt/ext_' }
			pkg := target.all_after(prefix).replace('_', '.')
			run('am force-stop ${pkg}')
			run('pkill -9 -f ${pkg}')
			run('pkill -9 -u $(stat -c %u /data/data/${pkg})')
			wipe_ram(target)
			run('umount -l ${target}')
		}
	}
	enc_list := os.execute('ls /data/local/tmp/*.enc').output.split_into_lines()
	for f in enc_list {
		if f.len > 5 {
			size_kb := os.execute('du -k ${f}').output.split('\t')[0]
			run('dd if=/dev/urandom of=${f} bs=1K count=${size_kb} conv=fsync')
			run('dd if=/dev/zero of=${f} bs=1K count=${size_kb} conv=fsync')
			run('rm -f ${f}')
		}
	}
	self := os.executable()
	self_size := os.execute('du -k ${self}').output.split('\t')[0]
	run('dd if=/dev/urandom of=${self} bs=1K count=${self_size} conv=fsync')
	run('rm -f ${self}')
	run('echo 3 > /proc/sys/vm/drop_caches')
	run('sync')
	run('sm fstrim')
	run('logcat -b all -c')
	run('reboot')
}

fn get_fg_app() string {
	return get_fg_app_safe() or { '' }
}

fn get_fg_app_safe() ?string {
	res := os.execute('dumpsys activity activities | grep "ResumedActivity"')
	if res.exit_code != 0 {
		return none
	}
	for line in res.output.split_into_lines() {
		if line.contains('/') {
			raw := line.all_before('/')
			parts := raw.trim_space().split(' ')
			if parts.len == 0 {
				continue
			}
			mut p := parts.last()
			if p.contains('{') {
				p = p.all_after_last('{')
			}
			if p.contains(':') {
				p = p.all_after_last(':')
			}
			p = p.replace('u0', '').trim_space()
			if p == '' {
				continue
			}
			return p
		}
	}
	return none
}

fn get_first_int(output string) int {
	parts := output.split('\t')
	if parts.len > 0 && parts[0] != '' {
		return parts[0].int()
	}
	return 0
}

fn get_gui_pw(pkg string) string {
	back_to_termuxapi()
	time.sleep(1000 * time.millisecond)
	uid := os.execute('stat -c %u /data/data/com.termux').output.trim_space()
	res := os.execute('su ${uid} -c "export PATH=/data/data/com.termux/files/usr/bin; export TMPDIR=/data/data/com.termux/files/usr/tmp; termux-dialog text -p -t \'${pkg} - MimicFS\' -i \'Enter Key\'"')

	if res.exit_code != 0 || !res.output.contains('"text":') {
		return ''
	}

	if res.output.contains('"code": -2') {
		return ''
	}

	raw := res.output
	pw := raw.all_after('"text": "').all_before('"')
	return pw.trim_space()
}

fn run_daemon(panic_pw string, time_count_str string, sync_count_str string, mg_str string) {
	kill_disk_swap()
	t_limit := time_count_str.int()
	sync := sync_count_str.int()
	mg := mg_str.int()
	if _unlikely_(t_limit <= 0 || sync < 0 || t_limit <= sync || mg < 0) {
		fatal('BAD_TIMER_CONF')
	}

	info('[MimicFS] Daemon Running ...')
	os.execute('su -c "dumpsys deviceidle whitelist +com.termux.api"')

	mut baseline := 0.0
	mut threshold := 0.0
	if mg != 0 {
		trigger_vibrate(400)
		baseline = get_mag_value_from_root()
		threshold = 15.0
	}
	mut tracked_apps := []TrackedApp{}
	mut last_app := ''
	
	files := os.ls('/data/local/tmp') or { [] }
	for file in files {
		if file.ends_with('.enc') && !file.ends_with('.ext.enc') {
			pkg := file.before('.enc')
			pid := pkg.replace('.', '_')

			if os.exists('/mnt/ram_${pid}') {
				info('    [ACTION] Key needed for ${pkg}')
				pw := get_gui_pw(pkg)
				if pw == '' {
					continue
				}
				if !tracked_apps.any(it.pkg_name == pkg) {
					tracked_apps << TrackedApp{
						pkg_name: pkg
						pw:       pw
						timer:    t_limit
						sync:     sync
					}
					success('${pkg} is now running in RAM')
				}
			}
		}
	}
	
	for {
		if mg != 0 {
			current_mag := get_mag_value_from_root()

			if current_mag > 0 {
				diff := math.abs(current_mag - baseline)
				if diff > threshold {
					warn('!!! HARDWARE ANOMALY DETECTED (Diff: ${diff}) !!!')
					trigger_vibrate(1000)
					for i in 0 .. tracked_apps.len {
						tracked_apps[i].timer = 0
					}
					baseline = current_mag
				}
			}
		}
		curr := get_fg_app()
		if curr != '' && curr != last_app {
			last_app = curr

			enc_path := '/data/local/tmp/${curr}.enc'
			if exists(enc_path) {
				pid := curr.replace('.', '_')
				mount_path := '/mnt/ram_${pid}'

				if !exists(mount_path) {
					info('    [ACTION] Key needed for ${curr}')
					run('am force-stop ${curr}')
					back_to_termuxapi()
					pw := get_gui_pw(curr)
					if pw == '' {
						continue
					}

					if pw == panic_pw {
						purge_all()
						break
					}

					if pw != '' {
						if start_app_core(curr, pw) == 0 && !tracked_apps.any(it.pkg_name == curr) {
							tracked_apps << TrackedApp{
								pkg_name: curr
								pw:       pw
								timer:    t_limit
								sync:     sync
							}
							success('${curr} is now running in RAM')
						}

						run("su -c 'pkg_name=\"${curr}\"; act_name=\$(cmd package resolve-activity --brief \$pkg_name | tail -n 1); am start -n \$act_name'")
					}
				}
			}
		}

		for i := 0; i < tracked_apps.len; i++ {
			mut t_app := tracked_apps[i]
			if curr == t_app.pkg_name {
				tracked_apps[i].timer = t_limit
				if sync != 0 {
					tracked_apps[i].sync--

					if tracked_apps[i].sync <= 0 {
						info('    [SYNC] Sync ${t_app.pkg_name} to ROM')
						stop_nokill_core(t_app.pkg_name, t_app.pw)
						tracked_apps[i].sync = sync
					}
				}
			} else {
				tracked_apps[i].timer--
				if tracked_apps[i].timer <= 0 {
					info('    [TIMEOUT] Closing ${t_app.pkg_name}')
					stop_app_core(t_app.pkg_name, t_app.pw)
					tracked_apps.delete(i)
					i--
					stop_nosave_core(t_app.pkg_name) // stop it again!
				}
			}
		}

		time.sleep(1000 * time.millisecond)
	}
}

fn add_pkg_core(pkg string, pw string) {
	pid := pkg.replace('.', '_')
	f := '/data/local/tmp/${pid}.enc'

	if _unlikely_(os.exists(f)) {
		fatal('DOUBLE_ADD: Package file already exists at ${f}')
	}

	start_app_core(pkg, pw)
	time.sleep(1000 * time.millisecond)
	stop_app_core(pkg, pw)
}

fn cpw_core(pkg string, pw string, new_pw string) {
	start_app_core(pkg, pw)
	time.sleep(1000 * time.millisecond)
	stop_app_core(pkg, new_pw)
}

fn rem_pkg_core(pkg string) {
	f := '/data/local/tmp/${pkg}.enc'
	ef := '/data/local/tmp/${pkg}.ext.enc'
	if _unlikely_(!exists(f)) {
		fatal('DOUBLE_REM')
	}
	mut files_to_wipe := [f]
	if exists(ef) {
		files_to_wipe << ef
	}
	for path in files_to_wipe {
		size_kb := os.execute('du -k "${path}"').output.split('\t')[0]
		run('dd if=/dev/urandom of="${path}" bs=1K count=${size_kb} conv=fsync')
		run('dd if=/dev/zero of="${path}" bs=1K count=${size_kb} conv=fsync')
		run('rm -f "${path}"')
	}
	run('sm fstrim')
}

fn list_core() {
	files := os.ls('/data/local/tmp') or { [] }
	println(term.bold('${'PACKAGE NAME':-35} | ${'STATUS':-10} | ${'STORAGE'}'))
	println('-'.repeat(60))

	for file in files {
		if file.ends_with('.enc') && !file.ends_with('.ext.enc') {
			pkg := file.before('.enc')
			pid := pkg.replace('.', '_')

			status := if exists('/mnt/ram_${pid}') {
				term.green('ALIVE')
			} else {
				term.gray('SLEEPING')
			}

			size := os.execute('du -h /data/local/tmp/${file}').output.split('\t')[0]
			println('${pkg:-35} | ${status:-10} | ${size}')
		}
	}
}

fn is_valid_pkg(s string) bool {
	if !os.exists("/data/data/${s}") {
		return false
	}
	if s.len == 0 {
		return false
	}
	mut has_dot := false

	for c in s {
		if c == `.` {
			has_dot = true
		} else if (c >= `a` && c <= `z`) || (c >= `0` && c <= `9`) {
			continue
		} else {
			error2('BAD_PKG_NAME')
			return false
		}
	}
	return has_dot
}

struct App {
mut:
	tui          &tui.Context = unsafe { nil }
	selected_idx int
	options      []string
}

fn get_input_dialog(title string, hint string, is_pw bool) string {
	back_to_termuxapi()
	time.sleep(1000 * time.millisecond)
	uid := os.execute('stat -c %u /data/data/com.termux').output.trim_space()
	p_flag := if is_pw { '-p' } else { '' }
	res := os.execute('su ${uid} -c "export PATH=/data/data/com.termux/files/usr/bin; export TMPDIR=/data/data/com.termux/files/usr/tmp; termux-dialog text ${p_flag} -t \'${title}\' -i \'${hint}\'"')
	if !res.output.contains('"text":') || res.output.contains('"code": -2') {
		return ''
	}
	return res.output.all_after('"text": "').all_before('"').trim_space()
}

fn extc_start(pkg string, path string, needed_data int) int {
	for b in pkg.bytes() {
		if !((b >= 97 && b <= 122) || (b >= 65 && b <= 90) || (b >= 48 && b <= 57) || b == 46 || b == 95) {
			return 1
		}
	}
	for b in path.bytes() {
		if !((b >= 97 && b <= 122) || (b >= 65 && b <= 90) || (b >= 48 && b <= 57)) {
			return 1
		}
	}

	s_path_1 := "/data/media/0/${path}"
	s_path_2 := "/storage/emulated/0/${path}"
	s_path_3 := "/mnt/extc_${path}"
	s_redp := "/mnt/runtime/write/emulated/0/${path}"

	if !os.exists(s_path_1) {
		return 1
	}

	stat_res := os.execute('stat -c %u /data/data/${pkg}')
	if stat_res.exit_code != 0 {
		return 1
	}
	u := stat_res.output.trim_space()

	run("umount -l ${s_path_1}")
	run("umount -l ${s_path_2}")
	run("umount -l ${s_redp}")
	run("umount -l ${s_path_3}")

	run("mkdir -p ${s_path_3}")

	if os.execute('mount -t tmpfs -o size=${needed_data}M,mode=771 tmpfs ${s_path_3}').exit_code == 0 {
		run("chown -R ${u}:${u} ${s_path_3}")
		run("chcon -R u:object_r:media_rw_data_file:s0 ${s_path_3}")
		run("chmod 777 ${s_path_3}")
		run("mount --bind ${s_path_3} ${s_path_2}")
		run("mount --bind ${s_path_3} ${s_path_1}")
		run('nsenter -t 1 -m mount --bind ${s_path_3} ${s_redp}')
		run('nsenter -t 1 -m mount --bind ${s_path_3} ${s_path_2}')
		run('nsenter -t 1 -m mount --bind ${s_path_3} ${s_path_1}')
		return 0
	}

	return 1
}

fn extc_stop(path string) int {
	for b in path.bytes() {
		if !((b >= 97 && b <= 122) || (b >= 65 && b <= 90) || (b >= 48 && b <= 57)) {
			return 1
		}
	}

	s_path_1 := "/data/media/0/${path}"
	s_path_2 := "/storage/emulated/0/${path}"
	s_path_3 := "/mnt/extc_${path}"
	s_redp := "/mnt/runtime/write/emulated/0/${path}"

	run("nsenter -t 1 -m umount -l ${s_path_1}")
	run("nsenter -t 1 -m umount -l ${s_path_2}")
	run("nsenter -t 1 -m umount -l ${s_redp}")
	run("umount -l ${s_path_1}")
	run("umount -l ${s_path_2}")
	run("umount -l ${s_path_3}")
	run("rm -rf ${s_path_3}")

	return 0
}

fn frame(x voidptr) {
	logo := "
	___  ____           _     ______ _____ 
	|  \\/  (_)         (_)    |  ___/  ___|
	| .  . |_ _ __ ___  _  ___| |_  \\ `--. 
	| |\\/| | | '_ ` _ \\| |/ __|  _|  `--. \\
	| |  | | | | | | | | | (__| |   /\\__/ /
	\\_|  |_/_|_| |_| |_|_|\\___\\_|   \\____/ 
	"
	mut app := unsafe { &App(x) }
	app.tui.clear()
	time.ticks()
	t := f64(time.ticks())
	speed := 0.003
	brightness := 152.0 + (102.0 * math.sin(t * speed))
	val := int(brightness)
	hex_color := (val << 16) | (val << 8) | val
	app.tui.draw_text(30, 4, term.hex(hex_color, logo))
	app.tui.draw_text(0, 2, term.gray('MimicFS | ver 2.0-Beta | Developed by zq | MIT License'))
	for i, opt in app.options {
		if i == app.selected_idx {
			app.tui.draw_text(2, 4 + i, term.red(' [>] ${opt}'))
		} else {
			app.tui.draw_text(4, 4 + i, opt)
		}
	}
	app.tui.draw_text(2, 20, term.gray('Arrows: Move | Enter: Action | Q: Exit'))
	app.tui.flush()
}

@[inline]
fn back_to_termux() {
	os.execute('su -c am start -n com.termux/.app.TermuxActivity')
}

@[inline]
fn back_to_termuxapi() {
	os.execute('su -c am start -n com.termux.api/.activities.TermuxAPIMainActivity')
	time.sleep(300 * time.millisecond)
}

@[inline]
fn sync_tapi() {
	back_to_termuxapi()
	back_to_termux()
}

fn event(e &tui.Event, x voidptr) {
	mut app := unsafe { &App(x) }
	if e.typ == .key_down {
		match e.code {
			.up {
				if app.selected_idx > 0 {
					app.selected_idx--
				}
			}
			.down {
				if app.selected_idx < app.options.len - 1 {
					app.selected_idx++
				}
			}
			._1 {
				app.selected_idx = 0
			}
			._2 {
				app.selected_idx = 1
			}
			._3 {
				app.selected_idx = 2
			}
			._4 {
				app.selected_idx = 3
			}
			._5 {
				app.selected_idx = 4
			}
			._6 {
				app.selected_idx = 5
			}
			._7 {
				app.selected_idx = 6
			}
			._8 {
				app.selected_idx = 7
			}
			._9 {
				app.selected_idx = 8
			}
			._0 {
				app.selected_idx = 9
			}
			.d {
				app.selected_idx = 11
			}
			.c {
				app.selected_idx = 12
			}
			.e {
				app.selected_idx = 13
			}
			.r {
				app.selected_idx = 14
			}
			.enter {
				println('')
				os.execute('clear')
				match app.selected_idx {
					0 {
						pkg := get_input_dialog('Add App', 'Package Name (e.g. org.telegram.messenger)',
							false)
						if !is_valid_pkg(pkg) {
							back_to_termux()
							return
						}
						pw := get_input_dialog('Set Key', 'Encryption Password', true)
						pw2 := get_input_dialog('Set Key Again', 'Encryption Password', true)
						if pw == '' || pw != pw2 {
							back_to_termux()
							return
						}
						back_to_termux()
						add_pkg_core(pkg, pw)
					}
					1 {
						pkg := get_input_dialog('Start App', 'Package Name', false)
						if !is_valid_pkg(pkg) {
							back_to_termux()
							return
						}
						pw := get_input_dialog('Enter Key', 'Password', true)
						if pw == '' {
							back_to_termux()
							return
						}
						back_to_termux()
						start_app_core(pkg, pw)
					}
					2 {
						pkg := get_input_dialog('Stop App', 'Package Name', false)
						if !is_valid_pkg(pkg) {
							back_to_termux()
							return
						}
						pw := get_input_dialog('Verify Key', 'Password', true)
						pw2 := get_input_dialog('Verify Key Again', 'Password', true)
						if pw == '' || pw2 != pw {
							back_to_termux()
							return
						}
						back_to_termux()
						stop_app_core(pkg, pw)
					}
					3 {
						p_pw := get_input_dialog('Daemon Setup', 'Panic Password (Wipe key)',
							true)
						if p_pw == '' {
							back_to_termux()
							return
						}
						tmo := get_input_dialog('Config', 'Auto-Lock Timeout (seconds)',
							false)
						if tmo == '' {
							back_to_termux()
							return
						}
						syn := get_input_dialog('Config', 'Sync Interval (seconds) - 0 to disable',
							false)
						if syn == '' {
							back_to_termux()
							return
						}
						mg := get_input_dialog('Config', 'Magnetic sensor (uT) - 0 to disable',
							false)
						if mg == '' {
							back_to_termux()
							return
						}
						back_to_termux()
						run_daemon(p_pw, tmo, syn, mg)
					}
					4 {
						list_core()
						time.sleep(3000 * time.millisecond)
					}
					5 {
						purge_all()
					}
					6 {
						pkg := get_input_dialog("Change App's password", 'Package Name',
							false)
						if !is_valid_pkg(pkg) {
							back_to_termux()
							return
						}
						pw := get_input_dialog('Verify Key', 'Password', true)
						pw2 := get_input_dialog('Verify Key Again', 'Password', true)
						if pw == '' || pw2 != pw {
							back_to_termux()
							return
						}
						new_pw := get_input_dialog('New Verify Key', 'Password', true)
						if new_pw == '' {
							back_to_termux()
							return
						}
						back_to_termux()
						cpw_core(pkg, pw, new_pw)
					}
					7 {
						pkg := get_input_dialog('Remove App', 'Package Name', false)
						if !is_valid_pkg(pkg) {
							back_to_termux()
							return
						}
						back_to_termux()
						rem_pkg_core(pkg)
					}
					8 {
						pkg := get_input_dialog('Force Stop App', 'Package Name', false)
						if !is_valid_pkg(pkg) {
							back_to_termux()
							return
						}
						back_to_termux()
						stop_nosave_core(pkg)
					}
					9 {
						pkg := get_input_dialog('Sync App', 'Package Name', false)
						if !is_valid_pkg(pkg) {
							back_to_termux()
							return
						}
						pw := get_input_dialog('Set Key', 'Encryption Password', true)
						pw2 := get_input_dialog('Set Key Again', 'Encryption Password', true)
						if pw == '' || pw2 != pw {
							back_to_termux()
							return
						}
						back_to_termux()
						stop_nokill_core(pkg, pw)
					}
					10 {
						exit(0)
					}
					11 {
						despy()
					}
					12 {
						space := get_input_dialog('Config', 'The size of space in GB',
							false).int()
						back_to_termux()
						if space > 0 { deep_cleaner_core(space) }
					}
					13 {
						pkg := get_input_dialog('Extc', 'Package Name', false)
						if !is_valid_pkg(pkg) {
							back_to_termux()
							return
						}
						path := get_input_dialog('Extc', 'Path Name (example /sdcard/yourpath = yourpath)', false)
						if path == ""  {
							back_to_termux()
							return
						}
						size := get_input_dialog('Config', 'the size of tmpfs (in MB)',
							false)
						if size != '' {
							extc_start(pkg, path, size.int())
						}
						back_to_termux()
					}
					14 {
						path := get_input_dialog('UnExtc', 'Path Name (example /sdcard/yourpath = yourpath)', false)
						back_to_termux()
						if path != "" {
							extc_stop(path)
						}
					}
					else {}
				}
			}
			.q {
				exit(0)
			}
			else {}
		}
	}
}

fn check_dp() {
	if os.execute('openssl 2>/dev/null').exit_code != 0 {
		fatal('There is no openssl installed')
	}
	if os.execute('zstd -h 2>/dev/null').exit_code != 0 {
		fatal('There is no zstd installed')
	}
	if os.execute('tar --help 2>/dev/null').exit_code != 0 {
		fatal('There is no tar installed')
	}
	if os.execute('shred --help 2>/dev/null').exit_code != 0 {
		fatal('There is no shred installed')
	}
	if os.execute('which termux-dialog 2>/dev/null').exit_code != 0 {
		fatal('There is no termux api installed OR you are in usermode')
	}
	if os.execute('ls /data/data/com.termux.api 2>/dev/null').exit_code != 0 {
		fatal('There is no termux api (apk file) installed')
	}
}

fn run_entropy_daemon() {
	u_raw := os.execute('stat -c %u /data/data/com.termux 2>/dev/null')
	if u_raw.exit_code != 0 {
		return
	}
	uid := u_raw.output.trim_space()

	mut out := os.open_file('/dev/urandom', 'w') or { return }
	defer { out.close() }

	for {
		cmd := 'su ${uid} -c "termux-sensor -s MAGNETOMETER -n 1" < /dev/null'
		res := os.execute(cmd)

		if res.exit_code == 0 && res.output.contains('"values":') {
			raw_vals := res.output.all_after('"values": [').all_before(']')
			ts := time.now().unix_nano()
			mono := time.sys_mono_now()
			seed := '${raw_vals}${ts}${mono}'

			entropy := sha256.sum(seed.bytes())
			out.write(entropy[..]) or { continue }
			out.flush()
		}
		time.sleep(5000 * time.millisecond)
	}
}

fn deep_cleaner_core(space int) {
	if os.execute("touch /sdcard/n").exit_code == 0 {
		os.execute("dd if=/dev/urandom of=/sdcard/n bs=1G count=${space} conv=fsync iflag=fullblock")
		os.execute("rm -rf /sdcard/n")
		os.execute("sync")
		os.execute("sm fstrim")
	} else {
		fatal("the program can not create the /sdcard/n file")
	}
}

fn main() {
	check_dp()
	spawn run_entropy_daemon()
	sync_tapi()
	run('shred -zu -n 5 ~/.bash_history && history -c')
	manage_snapshot_protection(true)

	raw_ops := [
		'1. ADD NEW APP',
		'2. START/MOUNT APP',
		'3. STOP/SYNC APP',
		'4. RUN WATCHDOG DAEMON',
		'5. LIST MANAGED APPS',
		'6. EMERGENCY PURGE',
		'7. CHANGE PASSWORD OF THE APP',
		'8. REMOVE ONE APP',
		'9. FORCE STOP APP',
		'0. SYNC APP',
		'Q. EXIT',
		'D. DESPY',
		'C. DEEP CLEANING',
		'E. EXTC [MOUNT A CUSTOM PATH FROM SDCARD]'
		'R. UNEXTC [UMOUNT A PATH FROM SDCARD]'
	]

	mut colored_ops := []string{}
	start_light := 250
	end_light := 150

	total := raw_ops.len

	for i, txt in raw_ops {
		level := start_light - (i * (start_light - end_light) / (total - 1))
		hex_color := (level << 16) | (level << 8) | level
		colored_ops << term.hex(hex_color, txt)
	}

	mut app := &App{
		options: colored_ops
	}

	app.tui = tui.init(
		user_data:    app
		frame_fn:     frame
		event_fn:     event
		window_title: 'MimicFS'
	)
	app.tui.run() or { return }
}
