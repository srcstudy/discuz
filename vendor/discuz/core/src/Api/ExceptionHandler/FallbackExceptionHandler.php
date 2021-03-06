<?php

/**
 * Copyright (C) 2020 Tencent Cloud.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace Discuz\Api\ExceptionHandler;

use Exception;
use Tobscure\JsonApi\Exception\Handler\ExceptionHandlerInterface;
use Tobscure\JsonApi\Exception\Handler\ResponseBag;

class FallbackExceptionHandler implements ExceptionHandlerInterface
{
    /**
     * @var bool
     */
    private $debug;

    /**
     * @param bool $debug
     */
    public function __construct($debug)
    {
        $this->debug = $debug;
    }

    /**
     * {@inheritdoc}
     */
    public function manages(Exception $e)
    {
        return true;
    }

    /**
     * {@inheritdoc}
     */
    public function handle(Exception $e)
    {
        $status = 500;
        $error = $this->constructError($e, $status);

        return new ResponseBag($status, [$error]);
    }

    /**
     * @param \Exception $e
     * @param $status
     *
     * @return array
     */
    private function constructError(Exception $e, $status)
    {
        return [
            'status' => (string) $status,
            'code' => $e->getMessage() ?: 'no_message',
        ];
    }
}
