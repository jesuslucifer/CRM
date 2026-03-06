import { authService } from "@/service/auth.service"
import type {
  ILoginRequest,
  IRegisterRequest,
  JwtResponse,
  SuccessResponse,
} from "@/types/auth.interface"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { useForm, type SubmitHandler } from "react-hook-form"
import { useNavigate, useLocation } from "react-router"
import { toast } from "react-toastify"

type AuthResponse = JwtResponse | SuccessResponse
type AuthRequest = ILoginRequest | IRegisterRequest

export function useAuthForm(isRegister: boolean) {
  const navigate = useNavigate()
  const location = useLocation()
  const queryClient = useQueryClient()

  const form = useForm<AuthRequest>({
    mode: "onChange",
  })

  const from = (location.state as any)?.from?.pathname || "/profile"

  const { mutate, isPending } = useMutation<
    AuthResponse,
    Error,
    AuthRequest
  >({
    mutationKey: [isRegister ? "register" : "login"],
    mutationFn: (data) =>
      isRegister
        ? authService.register(data as IRegisterRequest)
        : authService.login(data as ILoginRequest),

    onSuccess() {
      form.reset()
      queryClient.clear()
      toast.success(isRegister ? "Регистрация успешна" : "Авторизация успешна")
      navigate(from, { replace: true })
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