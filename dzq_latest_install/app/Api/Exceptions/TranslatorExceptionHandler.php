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

namespace App\Api\Exceptions;

use Exception;
use App\Exceptions\TranslatorException;
use Tobscure\JsonApi\Exception\Handler\ExceptionHandlerInterface;
use Tobscure\JsonApi\Exception\Handler\ResponseBag;

class TranslatorExceptionHandler implements ExceptionHandlerInterface
{
    /**
     * If the exception handler is able to format a response for the provided exception,
     * then the implementation should return true.
     *
     * @param \Exception $e
     *
     * @return bool
     */
    public function manages(Exception $e)
    {
        return $e instanceof TranslatorException;
    }

    /**
     * @param Exception $e
     * @return ResponseBag
     */
    public function handle(Exception $e)
    {
        $errors = [
            [
                'status' => $e->getCode(),
                'code' => $e->getMessage() ?: 'unknown_error',
            ]
        ];
        if (!empty($e->getDetail())) {
            $errors = array_merge($errors[0], ['detail' => $e->getDetail()]);
        }

        return new ResponseBag($e->getCode(), [$errors]);
    }
}
