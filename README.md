<h1 align="center">RDR2FullFrame</h1>

<p align="center">Removes the black bars from Red Dead Redemption 2 cutscenes on ultrawide.</p>

<p align="center">
  <img src="https://img.shields.io/badge/Windows-0078D6?style=flat-square&logo=windows&logoColor=white" alt="Windows">
  <img src="https://img.shields.io/badge/Red%20Dead%20Redemption%202-7B1E1E?style=flat-square" alt="RDR2">
  <img src="https://img.shields.io/badge/single%20player-safe-2ea44f?style=flat-square" alt="single player safe">
  <img src="https://img.shields.io/badge/license-MIT-f1c40f?style=flat-square" alt="MIT license">
</p>

---

RDR2 runs gameplay at your full ultrawide resolution but squeezes cutscenes and the
cinematic camera into a box with black bars. RDR2FullFrame removes those bars. The
picture is not stretched, you just get the full screen the same way gameplay does.

It is a small background app. Run it, leave it open, play.

## Requirements

- Windows and a 64-bit copy of RDR2 (tested on the Steam version).
- **Smart App Control must be off.** It blocks apps that are not code signed, and this
  one is not. Settings &rarr; Privacy & security &rarr; Windows Security &rarr; App &
  browser control &rarr; Smart App Control.
- Single player only. Do not run it with Red Dead Online.

## Download and use

1. Download `RDR2FullFrame.zip` from the [Releases](../../releases) page.
2. Unzip it somewhere normal like your Desktop (not inside Program Files).
3. Run `RDR2FullFrame.exe` and leave the little window open.
4. Play RDR2. Cutscenes and the cinematic camera now fill the screen.

You can start it before or after the game, it waits for RDR2 either way. Want it
automatic? Put a shortcut to it in your Startup folder (`Win+R`, then `shell:startup`).

## Will I get banned?

No. RDR2's anti-cheat only runs in Red Dead Online. Story mode has none, so this is
safe in single player. Just never run it while you are in Online.

Antivirus might warn about it, because it reads the game's memory like a trainer does.
Nothing is installed and no game files are changed. The full source is in this repo if
you want to read exactly what it does.

---

<details>
<summary><b>How it works</b></summary>

The bars are not a cropped image. The engine draws the full widescreen frame and then
paints black bars on top, turned on by a single byte in the game's code:

```
mov byte ptr [letterbox_flag], 01    ; 01 = draw the bars
```

RDR2FullFrame finds that instruction in the running game and changes the `01` to `00`,
so the bars are never drawn. It only reads and writes memory, so nothing is installed
and no game files are changed.

This removes the top and bottom bars. If a cutscene ever shows narrow bars on the left
and right too, that is a separate value and can be added later. A big RDR2 update could
move the code, in which case the app would need an update to find it again.

</details>

## Build it yourself

It builds with the MinGW-w64 toolchain on Windows.

1. Get the code: click the green **Code** button at the top of this page and
   choose **Download ZIP**, then unzip it (or `git clone` the repo).
2. Install [MSYS2](https://www.msys2.org) and open the **MSYS2 MINGW64** shell.
3. Install the build tools (the compiler and the `make` tool):

   ```
   pacman -S mingw-w64-x86_64-toolchain make
   ```
4. Go to the folder from step 1 (your `C:` drive shows up as `/c`) and build:

   ```
   cd /c/Users/you/RDR2FullFrame
   make
   ```

You get `build\RDR2FullFrame.exe`, with the `finder.exe` diagnostic alongside it.

## License

MIT. See [LICENSE](LICENSE).
