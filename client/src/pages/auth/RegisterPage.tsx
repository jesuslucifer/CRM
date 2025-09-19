import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { useAuthForm } from "@/shared/hooks/useAuthForm"
import { NavLink } from "react-router"

export default function RegisterPage() {
  const { form, onSubmit, isPending } = useAuthForm(true) // true = register

  return (
    <div className="flex items-center justify-center min-h-screen bg-gradient-to-br from-blue-50 to-indigo-50">
      <Card className="w-[400px] shadow-2xl rounded-2xl overflow-hidden">
        <CardHeader className="bg-gradient-to-r from-indigo-500 to-blue-500 text-white p-6">
          <CardTitle className="text-2xl font-bold">Регистрация</CardTitle>
          <CardDescription>Создайте новый аккаунт</CardDescription>
        </CardHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="p-6 space-y-4">
            <FormField
              control={form.control}
              name="username"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Имя пользователя</FormLabel>
                  <FormControl>
                    <Input placeholder="username123" {...field} />
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
                  <FormLabel>Email</FormLabel>
                  <FormControl>
                    <Input type="email" placeholder="user@example.com" {...field} />
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
                  <FormLabel>Пароль</FormLabel>
                  <FormControl>
                    <Input type="password" placeholder="••••••••" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <CardFooter className="flex flex-col gap-3 p-0">
              <Button type="submit" className="w-full bg-gradient-to-r from-indigo-500 to-blue-500 hover:from-blue-500 hover:to-indigo-500 text-white font-semibold py-3" disabled={isPending}>
                {isPending ? "Регистрируем..." : "Зарегистрироваться"}
              </Button>
              <p className="text-center text-sm text-gray-500">
                Уже есть аккаунт?{" "}
                <NavLink to="/login" className="text-indigo-600 hover:underline">
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
