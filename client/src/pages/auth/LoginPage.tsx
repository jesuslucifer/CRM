import { Button } from "@/components/ui/button"
import {
  Card,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { useAuthForm } from "@/shared/hooks/useAuthForm"
import { NavLink } from "react-router"

export default function LoginPage() {
  const { form, onSubmit, isPending } = useAuthForm(false)

  return (
    <div className="relative flex items-center justify-center min-h-screen bg-[url('../../../public/ff0ee979e682bbb84cce4e725a999682.jpg')] bg-cover overflow-hidden">

      <div className="absolute w-[600px] h-[600px] bg-indigo-600/20 blur-[140px] rounded-full -top-40 -left-40" />
      <div className="absolute w-[500px] h-[500px] bg-purple-600/20 blur-[140px] rounded-full bottom-0 right-0" />

      <Card className="relative w-[420px] bg-white/5 backdrop-blur-2xl border border-white/10 shadow-2xl rounded-3xl p-8">
        <CardHeader className="p-0 mb-6 text-center">
          <CardTitle className="text-3xl font-semibold text-white">
            Добро пожаловать
          </CardTitle>
          <CardDescription className="text-slate-700">
            Войдите в свой аккаунт
          </CardDescription>
        </CardHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-5">
            <FormField
              control={form.control}
              name="usernameOrEmail"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-white">
                    Email или имя пользователя
                  </FormLabel>
                  <FormControl>
                    <Input
                      placeholder="user@example.com"
                      {...field}
                      className="h-11 rounded-xl bg-white/10 border-white/10 text-white focus:ring-2 focus:ring-indigo-500"
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="password"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-white">
                    Пароль
                  </FormLabel>
                  <FormControl>
                    <Input
                      type="password"
                      placeholder="••••••••"
                      {...field}
                      className="h-11 rounded-xl bg-white/10 border-white/10 text-white focus:ring-2 focus:ring-indigo-500"
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <CardFooter className="flex flex-col gap-4 p-0 pt-4">
              <Button
                type="submit"
                disabled={isPending}
                className="w-full h-11 rounded-xl bg-white text-black hover:bg-slate-200 font-medium transition"
              >
                {isPending ? "Входим..." : "Войти"}
              </Button>

              <div className="space-y-2 text-center text-sm text-slate-400">
                <p>
                  Нет аккаунта?{" "}
                  <NavLink
                    to="/register"
                    className="text-white hover:underline"
                  >
                    Зарегистрироваться
                  </NavLink>
                </p>
                <p>
                  <NavLink
                    to="/forgot-password"
                    className="hover:underline"
                  >
                    Забыли пароль?
                  </NavLink>
                </p>
              </div>
            </CardFooter>
          </form>
        </Form>
      </Card>
    </div>
  )
}