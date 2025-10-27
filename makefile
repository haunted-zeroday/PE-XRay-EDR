CC = g++
CFLAGS = -Iinclude -Icore/include -m64 -O2 -s -DNDEBUG
LDIR = -Llib 

CORE_SRCS = core/pe_analyzer.c core/src/pe_x86.c core/src/pe_x64.c src/addons.c

GUI_LIBS = -liup -liupcd -liupimglib -liupim \
       -lcd -lim -lz \
       -lgdi32 -lcomctl32 -lole32 -loleaut32 -luuid -lwintrust -lwindowscodecs -lshlwapi
GUI_LDFLAGS = -mwindows -static

gui: main.c $(CORE_SRCS) icons.o
	windres --target=pe-x86-64 icons.rc -o icons.o
	$(CC) $(CFLAGS) $^ -o PE-XRay.exe $(GUI_LDFLAGS) $(LDIR) $(GUI_LIBS)

CLI_LIBS = -lshlwapi -lwintrust
CLI_LDFLAGS = -mconsole -static

cli: cli_main.c $(CORE_SRCS)
	$(CC) $(CFLAGS) $^ -o pexray-cli.exe $(CLI_LDFLAGS) $(LDIR) $(CLI_LIBS)

all: gui cli