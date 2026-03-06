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

export default function RegisterPage() {
  const { form, onSubmit, isPending } = useAuthForm(true)

  return (
    <div className="relative flex items-center justify-center min-h-screen bg-[#0f172a] overflow-hidden">

      {/* Background glow */}
      <div className="absolute w-[600px] h-[600px] bg-indigo-600/20 blur-[140px] rounded-full -top-40 -left-40" />
      <div className="absolute w-[500px] h-[500px] bg-purple-600/20 blur-[140px] rounded-full bottom-0 right-0" />

      <Card className="relative w-[420px] bg-white/5 backdrop-blur-2xl border border-white/10 shadow-2xl rounded-3xl p-8">
        <CardHeader className="p-0 mb-6 text-center">
          <CardTitle className="text-3xl font-semibold text-white">
            Создать аккаунт
          </CardTitle>
          <CardDescription className="text-slate-400">
            Заполните данные для регистрации
          </CardDescription>
        </CardHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-5">

            <FormField
              control={form.control}
              name="username"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-slate-300">
                    Имя пользователя
                  </FormLabel>
                  <FormControl>
                    <Input
                      placeholder="username123"
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
              name="email"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-slate-300">
                    Email
                  </FormLabel>
                  <FormControl>
                    <Input
                      type="email"
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
                  <FormLabel className="text-slate-300">
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
                {isPending ? "Создание..." : "Зарегистрироваться"}
              </Button>

              <p className="text-center text-sm text-slate-400">
                Уже есть аккаунт?{" "}
                <NavLink
                  to="/login"
                  className="text-white hover:underline"
                >
                  Войти
                </NavLink>
              </p>
            </CardFooter>
          </form>
        </Form>
      </Card>
    </div>
  )
}