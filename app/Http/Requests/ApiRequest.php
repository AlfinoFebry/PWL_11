<?php

namespace App\Http\Requests;

use App\traits\ApiResponse;
use Illuminate\Contracts\Validation\Validator;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Http\Exceptions\HttpResponseException;
use Symfony\Component\HttpFoundation\Response;

abstract class ApiRequest extends FormRequest
{
    use ApiResponse;
    
    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, mixed>
     */
    abstract public function rules();

    protected function failedValidation(Validator $validator)
    {
        throw new HttpResponseException($this->apiError($validator->errors(),
        Response::HTTP_UNPROCESSABLE_ENTITY));
    }

    protected function failedAuthorization()
    {
        throw new HttpResponseException($this->apiError(null,
        Response::HTTP_UNAUTHORIZED));
    }
}
