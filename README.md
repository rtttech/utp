# utp - A Well Designed and Easy-to-Use uTorrent Transport Protocol Library.

[uTP](http://www.bittorrent.org/beps/bep_0029.html) (uTorrent transport protocol) is a transport protocol which uses [Low Extra Delay Background Transport (LEDBAT)](http://datatracker.ietf.org/wg/ledbat/charter/) for its congestion controller.

LEDBAT congestion control has the following goals:

1. Try to use all available bandwidth, and to maintain a low queueing delay when no other traffic is present.
2. Limit the queuing delay it adds to that induced by other traffic.
3. To yield quickly to standard TCP that share the same bottleneck link.

## The API

[API Doc](api_doc.md)

## Building

### Linux/MACOSX
cmake ./

make

### Windows
cmake ./

open Project.sln with visual studio

## License

utp is released under the MIT license.

Copyright (c) 2020 LibEasyGet, RTTTECH, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
