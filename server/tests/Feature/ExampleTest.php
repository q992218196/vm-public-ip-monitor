<?php

namespace Tests\Feature;

// use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class ExampleTest extends TestCase
{
    /**
     * A basic test example.
     */
    public function test_only_health_and_api_routes_are_exposed(): void
    {
        $this->get('/')->assertNotFound();
        $this->get('/admin/login')->assertNotFound();
        $this->get('/up')->assertOk();
        $this->getJson('/api/v1/agent/update?version=0.4.1')->assertUnauthorized();
    }
}
