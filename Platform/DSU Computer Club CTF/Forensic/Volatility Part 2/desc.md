Volatility Part 2
375
Before my computer crashed, I had been in the middle of painting a second flag as well. Can you look around the memory dump some more and see if you can recover the flag I was painting? Oh, and for whatever reason, paint gave my BGR .bmp flag painting dimensions of width 614 px and height 460 px. Maybe that'll help you recover it more efficiently, I dunno. Just get me my painting back please!

Author: Jacob R.

Note: Use the same memory dump from Part 1 for this challenge. Additionally, Part 1 does not have to be solved before Part 2, however Part 1 is less difficult and should help you get a basic idea of how to use Volatility.

Hint
×
1. To help you find the correct GIMP settings for recovering the painting, try using different multiples of the width and then narrowing it down once you find the approximate offset.

2. This part kind of takes a lot of trial and error. When I was testing the challenge, I found that searching for it using multiples of the width dimension helped narrow down the correct offset. For example, instead of using 614 pixels I used 1228 pixels when looking, then changed it back to 614 when I found the approximate offset in order to make the image more clear.

3. As another hint, the offset should be closer to the beginning than the end. The image you are looking for will have a white background with some squiggly lines and a couple words, so if you see anything like that then it is probably what you are looking for

4. BGRX should be correct. You'll also want to change the width and height settings. The image you're trying to find has a width of 614 and a height of 400.

5. I actually think it should be RGB 24 bit with BGR layout
