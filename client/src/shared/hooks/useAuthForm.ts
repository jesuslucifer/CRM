// shared/hooks/useAuthForm.ts

import { authService } from "@/service/auth.service"
import type { ILoginRequest, IRegisterRequest, JwtResponse, SuccessResponse } from "@/types/auth.interface"
import { useMutation } from "@tanstack/react-query"
import { useForm, type SubmitHandler } from "react-hook-form"
import { useNavigate } from "react-router"
import { toast } from "react-toastify"

 

type AuthResponse = JwtResponse | SuccessResponse
type AuthRequest = ILoginRequest | IRegisterRequest

export function useAuthForm(isRegister: boolean) {
  const navigate = useNavigate()

  const form = useForm<AuthRequest>({
    mode: "onChange",
  })

  const { mutate, isPending } = useMutation<AuthResponse, Error, AuthRequest>({
    mutationKey: [isRegister ? "register" : "login"],
    mutationFn: (data) =>
      isRegister
        ? authService.register(data as IRegisterRequest)
        : authService.login(data as ILoginRequest),

    onSuccess(data) {
      form.reset()
        navigate("/profile")

      // if (!isRegister && "accessToken" in data) {
      //   toast.success("Успешная авторизация")
      //   navigate("/dashboard")
      // } else {
      //   toast.success("Регистрация прошла успешно")
      //   navigate("/login")
      // }
    },

    onError(error: any) {
      toast.error(error?.message || "Ошибка при авторизации")
    },
  })

  const onSubmit: SubmitHandler<AuthRequest> = (data) => {
    mutate(data)
  }

  return { form, onSubmit, isPending }
}
