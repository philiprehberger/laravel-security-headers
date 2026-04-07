<?php

declare(strict_types=1);

namespace PhilipRehberger\SecurityHeaders;

enum CspDirective: string
{
    case DefaultSrc = 'default-src';
    case ScriptSrc = 'script-src';
    case StyleSrc = 'style-src';
    case ImgSrc = 'img-src';
    case FontSrc = 'font-src';
    case ConnectSrc = 'connect-src';
    case MediaSrc = 'media-src';
    case FrameSrc = 'frame-src';
    case BaseUri = 'base-uri';
    case FormAction = 'form-action';
    case FrameAncestors = 'frame-ancestors';
}
