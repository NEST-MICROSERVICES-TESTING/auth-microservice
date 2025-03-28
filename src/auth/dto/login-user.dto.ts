import { IsEmail, IsString, IsStrongPassword, MinLength } from "class-validator";

export class LoginUserDto {
    
    @IsString()
    @IsEmail()
    sEmail      : string;

    @IsString()
    @IsStrongPassword()
    sPassword   : string;
}