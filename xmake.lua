set_project("gozinject")
set_version("1.0.0")

add_rules("mode.debug", "mode.release")

local function join_path(...)
	local parts = { ... }
	return table.concat(parts, "/"):gsub("//+", "/")
end

local function basename(p)
	return (p:gsub("[\\/]+$", ""):match("([^\\/]+)$")) or p
end

---------------------------------------------------------------------------
-- Hand-written AArch64 shellcode
--
-- Each .s is assembled to a flat .bin that src/shellcode_builder.go //go:embed-s.
-- The .bin blobs are checked in; the `injector` build reassembles each .s and
-- fails if it no longer matches the committed .bin (so an edited source can never
-- silently ship a stale stub/stage), and `xmake stubgen` regenerates them after
-- an intentional edit.
---------------------------------------------------------------------------

local shellcode_stubs = {
	{ src = "custom_stub.s", bin = "src/custom_stub.bin" },
	{ src = "stage_dlopen.s", bin = "src/stage_dlopen.bin" },
}

-- Returns (as_path, objcopy_path), or (nil, nil) when no AArch64 assembler is
-- found. `find_program` must be passed in by the caller via
-- `import("lib.detect.find_program")` — `import` is only available in the build
-- sandbox scope (on_build/on_run), not in this file-scope helper's closure.
local function find_aarch64_asm(find_program)
	local as = find_program("aarch64-linux-gnu-as")
	local objcopy = find_program("aarch64-linux-gnu-objcopy")
	if as and objcopy then
		return as, objcopy
	end
	return nil, nil
end


---------------------------------------------------------------------------
-- Targets
---------------------------------------------------------------------------

target("injector")
set_kind("phony")
on_build(function(target)
	local output = join_path(os.projectdir(), "dist", "injector")
	os.mkdir(join_path(os.projectdir(), "dist"))
	os.mkdir(join_path(os.projectdir(), "dist", "tmp"))

	-- Shellcode drift guard: reassemble each .s and verify it still matches the
	-- committed (//go:embed-ed) .bin. Skipped when no AArch64 assembler is present
	-- so a Go-only environment can still build — CI with binutils enforces it.
	local find_program = import("lib.detect.find_program")
	local as, objcopy = find_aarch64_asm(find_program)
	if as and objcopy then
		for _, st in ipairs(shellcode_stubs) do
			local obj = os.tmpfile() .. ".o"
			local tmpbin = os.tmpfile() .. ".bin"
			os.vrunv(as, { join_path(os.projectdir(), st.src), "-o", obj })
			os.vrunv(objcopy, { "-O", "binary", obj, tmpbin })
			local got = io.readfile(tmpbin, { encoding = "binary" })
			local want = io.readfile(join_path(os.projectdir(), st.bin), { encoding = "binary" })
			os.tryrm(obj)
			os.tryrm(tmpbin)
			if got ~= want then
				raise("shellcode drift: reassembling " .. st.src .. " no longer matches committed " .. st.bin
					.. ".\nYou edited the source without regenerating the embedded binary (and likely the offset\n"
					.. "constants in src/shellcode_builder.go). Run `xmake stubgen`, re-derive the constants from\n"
					.. "the new labels, then rebuild. (If only your assembler VERSION differs, `xmake stubgen`\n"
					.. "refreshes the committed .bin to match.)")
			end
		end
		print("shellcode drift guard: ok (custom_stub/stage_dlopen .bin match .s)")
	else
		print("shellcode drift guard: skipped (no aarch64-linux-gnu-as/objcopy; install binutils-aarch64-linux-gnu to enable)")
	end

	print("Building gozinject for android/arm64 ...")
	os.vrunv("go", { "build", "-trimpath", "-ldflags=-s -w", "-o", output, "./src" }, {
		envs = {
			GOOS = "android",
			GOARCH = "arm64",
			CGO_ENABLED = "0",
			GOTMPDIR = join_path(os.projectdir(), "dist", "tmp"),
		},
	})
end)
on_clean(function(target)
	os.tryrm(join_path(os.projectdir(), "dist", "injector"))
end)
target_end()

---------------------------------------------------------------------------
-- Tasks
---------------------------------------------------------------------------

task("run")
set_menu({
	usage = "xmake run [options]",
	description = "Build, deploy, and run the injector on device",
	options = {
		{ "s", "serial", "kv", nil, "ADB device serial" },
		{ nil, "pkg", "kv", "com.termux", "Target package" },
		{ nil, "lib", "kv", nil, "Path(s) to library to inject (local); comma-separated, injected in order" },
		{ nil, "logcat", "k", nil, "Stream child logcat after injection" },
		{ nil, "logtag", "kv", nil, "Stream child logcat filtered to TAG (raw format); implies --logcat" },
		{ nil, "vma-hide", "kv", nil, "/proc/vma_hide use: auto (default) | always | never" },
		{ nil, "autostart-symbol", "kv", nil, "Optional payload symbol to call after dlopen" },
		{ nil, "autostart-arg", "kv", nil, "Optional string argument for --autostart-symbol" },
		{ nil, "debug", "k", nil, "Enable debug logging" },
	},
})
on_run(function()
	local opt = import("core.base.option")
	local pkg = opt.get("pkg")
	local serial = opt.get("serial")
	local local_lib = opt.get("lib")
	local want_logcat = opt.get("logcat")
	local want_logtag = opt.get("logtag")
	local want_vma_hide = opt.get("vma-hide")
	local want_autostart_symbol = opt.get("autostart-symbol")
	local want_autostart_arg = opt.get("autostart-arg")
	local want_debug = opt.get("debug")

	-- --lib is comma-separated; injected in the order given.
	local function split_csv(s)
		local out = {}
		for part in string.gmatch(s or "", "([^,]+)") do
			part = part:gsub("^%s+", ""):gsub("%s+$", "")
			if #part > 0 then table.insert(out, part) end
		end
		return out
	end

	local local_libs = split_csv(local_lib)
	if #local_libs == 0 then
		print("Error: --lib is required (path to .so payload; comma-separated for multiple)")
		return
	end

	local remote_tmp = "/data/local/tmp"

	local function adb(args)
		local full = serial and { "-s", serial } or {}
		for _, v in ipairs(args) do
			table.insert(full, v)
		end
		os.vrunv("adb", full)
	end

	local function adb_su(args)
		local full = serial and { "-s", serial } or {}
		table.insert(full, "shell")
		table.insert(full, "-tt")
		table.insert(full, "su")
		table.insert(full, "-c")
		table.insert(full, '"' .. table.concat(args, " ") .. '"')
		os.vrunv("adb", full)
	end

	-- Build
	os.vrunv("xmake", { "b", "injector" })

	-- Randomized injector name on device (cleanup always runs)
	local remote_injector_name = string.format("app_process_%04x", math.random(0, 0xffff))
	local remote_injector = remote_tmp .. "/" .. remote_injector_name

	-- Deploy
	print("Deploying to device...")
	adb({ "push", "dist/injector", remote_injector })
	adb_su({ "chmod", "755", remote_injector })
	local remote_libs = {}
	for _, ll in ipairs(local_libs) do
		local rl = remote_tmp .. "/" .. basename(ll)
		adb({ "push", ll, rl })
		table.insert(remote_libs, rl)
	end

	-- Build injector command
	print("Running injector for package: " .. pkg)
	local run_args = serial and { "-s", serial } or {}
	table.insert(run_args, "shell")
	table.insert(run_args, "-tt")
	table.insert(run_args, "su")
	table.insert(run_args, "-c")

	local injector_cmd = remote_injector .. " -pkg " .. pkg
	for _, rl in ipairs(remote_libs) do
		injector_cmd = injector_cmd .. " -lib " .. rl
	end
	if want_debug then injector_cmd = injector_cmd .. " -debug" end
	if want_logcat then injector_cmd = injector_cmd .. " -logcat" end
	if want_logtag then injector_cmd = injector_cmd .. " -logtag " .. want_logtag end
	if want_vma_hide then injector_cmd = injector_cmd .. " -vma-hide " .. want_vma_hide end
	if want_autostart_symbol then injector_cmd = injector_cmd .. " -autostart-symbol " .. want_autostart_symbol end
	if want_autostart_arg then injector_cmd = injector_cmd .. " -autostart-arg " .. want_autostart_arg end
	table.insert(run_args, '"' .. injector_cmd .. '"')

	os.execv("adb", run_args)

	-- Cleanup device artifacts
	print("Cleaning up device artifacts...")
	adb_su({ "rm", "-f", remote_injector })
	for _, rl in ipairs(remote_libs) do
		adb_su({ "rm", "-f", rl })
	end
end)
task_end()

-- Regenerate the embedded shellcode binaries after editing a .s source. The
-- `injector` build's drift guard fails until the committed .bin matches the .s,
-- so run this whenever you touch custom_stub.s / stage_dlopen.s.
task("stubgen")
set_menu({ description = "Reassemble custom_stub.s / stage_dlopen.s into src/*.bin (run after editing a .s)" })
on_run(function()
	local find_program = import("lib.detect.find_program")
	local as, objcopy = find_aarch64_asm(find_program)
	if not (as and objcopy) then
		raise("stubgen needs aarch64-linux-gnu-as + aarch64-linux-gnu-objcopy (install binutils-aarch64-linux-gnu)")
	end
	for _, st in ipairs(shellcode_stubs) do
		local obj = os.tmpfile() .. ".o"
		local tmpbin = os.tmpfile() .. ".bin"
		os.vrunv(as, { join_path(os.projectdir(), st.src), "-o", obj })
		os.vrunv(objcopy, { "-O", "binary", obj, tmpbin })
		io.writefile(join_path(os.projectdir(), st.bin), io.readfile(tmpbin, { encoding = "binary" }), { encoding = "binary" })
		os.tryrm(obj)
		os.tryrm(tmpbin)
		print("regenerated " .. st.bin .. " from " .. st.src)
	end
	print("stubgen done. If any label moved, re-derive the offset constants in src/shellcode_builder.go.")
end)
task_end()
