import { userService, type IChangePassword } from "@/service/user.service"
import { useMutation, useQuery } from "@tanstack/react-query"
import { useNavigate } from "react-router"
import { toast } from "react-toastify"

export interface IForgotPassword {
   email: string
}
export interface IChangeEmail {
   email: string,
   password: string
}
export function useGetUserById(id: number) {

   return useQuery({
      queryKey: ['user'],
      queryFn: () => userService.getUserById(id)
   })
}

export function useGetAllUsers() {

   return useQuery({
      queryKey: ['users'],
      queryFn: userService.getAllUsers
   })
}
export function useForgotPassword() {
   const navigate = useNavigate();
   const { mutate, isPending } = useMutation({
      mutationKey: ['forgot-password'],
      mutationFn: (data: IForgotPassword) => userService.forgotPassword(data),
      onSuccess: () => {
         // navigate('/login');
         console.log('good');
         toast.success("Письмо отправлено на почту")
      },
      onError(error: any) {
         toast.error(error?.message || "Ошибка при смене пароля")
      },
   })
   const onSubmit = (email: string) => {
      mutate({ email })
   }
   return { onSubmit, isPending }
}
export function useChangePassword() {
   const navigate = useNavigate();
   const { mutate, isPending } = useMutation({
      mutationKey: ['change-password'],
      mutationFn: (data: IChangePassword) => userService.changePassword(data),
      onSuccess: () => {
         // navigate('/login');
         console.log('good')
         toast.success("Пароль изменен")
      },
      onError(error: any) {
         toast.error(error?.message || "Ошибка при смене пароля")
      },
   })
   const onSubmit = (currentPassword: string, newPassword: string) => {
      mutate({ currentPassword, newPassword })
   }
   return { onSubmit, isPending }
}
export function useChangeEmail() {
   const navigate = useNavigate();
   const { mutate, isPending } = useMutation({
      mutationKey: ['change-email'],
      mutationFn: (data: IChangeEmail) => userService.changeEmail(data),
      onSuccess: () => {
         // navigate('/login');
         console.log('good')
         toast.success("Почта изменена")
      },
      onError(error: any) {
         toast.error(error?.message || "Ошибка при смене почты")
      },
   })
   const onSubmit = (email: string, password: string) => {
      mutate({ email, password })
   }
   return { onSubmit, isPending }
}