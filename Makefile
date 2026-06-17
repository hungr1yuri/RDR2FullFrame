# RDR2FullFrame build script - compiles the exe that ships in the release.
# Toolchain: MinGW-w64 (Windows via w64devkit/MSYS2, or cross-compile on Linux).
#
#   make           build RDR2FullFrame.exe (+ RDR2FullFrame.ini) and finder.exe into build/
#   make rdr2fullframe  the patcher you run
#   make finder    diagnostic / value scanner
#   make clean
#
# Run RDR2FullFrame.exe from a writable folder (the build folder works), not from
# inside Program Files, so it can write its log.

# MinGW-w64 toolchain. On a native Windows MinGW setup the tools are g++ and
# windres; some toolchains expose the target-prefixed names instead. Use
# whichever is on PATH so plain `make` works either way.
CXX      := $(shell command -v x86_64-w64-mingw32-g++ >/dev/null 2>&1 && echo x86_64-w64-mingw32-g++ || echo g++)
WINDRES  := $(shell command -v x86_64-w64-mingw32-windres >/dev/null 2>&1 && echo x86_64-w64-mingw32-windres || echo windres)
CXXFLAGS := -O2 -std=c++17 -Wall -Wextra -Wno-cast-function-type -municode
LDSTATIC := -static -static-libgcc -static-libstdc++ -s

BUILD    := build

.PHONY: all rdr2fullframe finder clean
all: rdr2fullframe finder

# Icon + version info, compiled to a COFF object and linked into the exe.
$(BUILD)/app.o: src/app.rc src/app.ico | $(BUILD)
	$(WINDRES) -I src $< -O coff -o $@

rdr2fullframe: $(BUILD)/RDR2FullFrame.exe
$(BUILD)/RDR2FullFrame.exe: src/rdr2fullframe.cpp src/mem.cpp src/mem.h $(BUILD)/app.o | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ src/rdr2fullframe.cpp src/mem.cpp $(BUILD)/app.o $(LDSTATIC)
	cp -f RDR2FullFrame.ini $(BUILD)/RDR2FullFrame.ini
	@echo "built $@"

finder: $(BUILD)/finder.exe
$(BUILD)/finder.exe: src/finder.cpp src/mem.cpp src/mem.h | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ src/finder.cpp src/mem.cpp $(LDSTATIC)
	@echo "built $@"

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)
