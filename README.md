# hal-actionscript-extractor
Extractor for "action scripts" used in NES and SNES games developed by HAL Laboratory

**(This page is still a work-in-progress)**

## Getting started
```console
$ python actionscript_dumper.py -s symbols.txt -a asm_funcs.txt earthbound.smc output.txt
```

## Requirements
- Python 3.6+

## TODO
- Modularize the extractor code so a module can be loaded and configured per-game, instead of having multiple copies of essentially the same program.
- Look into Kirby Super Star action scripts.


## FAQ
### "Action Script"? What the hey is that?
HAL used a sort of scripting Virtual Machine to help in developing games quicker. With this system, each game object/entity runs a "main" script and possibly multiple sub-scripts, which I have come to personally call "tasks". It is a really versatile system, but it comes with some cost in CPU cycles, since scripts have to be interpreted (this seems especially apparent in Kirby's Adventure).\
It is believed that Satoru Iwata implemented this Virtual Machine.[^1]


### What's with the name? Where did it come from?
The name "action script" comes from Marcus Lindblom's localization files for Earthbound[^2], where each NPC dialogue had a commented "info header" about
the NPC, which included the used sprite, general map location, their "ActionScript", among other things.\
Earthbound hackers have noticed these "ActionScript" descriptions most of the time matched up with what they previously called "movement scripts", and so the name "action script" was adopted in favor of the old name.

[^1]: https://www.4gamer.net/games/999/G999905/20151225009/index_2.html
[^2]: https://gamehistory.org/earthbound-script-files/
