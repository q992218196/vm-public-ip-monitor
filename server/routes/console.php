<?php

use Illuminate\Support\Facades\Schedule;

Schedule::command('monitor:dispatch')->everyTenSeconds()->withoutOverlapping();
Schedule::command('monitor:maintain')->everyFiveMinutes()->withoutOverlapping();
