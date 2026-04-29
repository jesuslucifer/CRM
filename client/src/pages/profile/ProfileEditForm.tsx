import { Input } from "@/components/ui/input"
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
} from "@/components/ui/form"
import { useForm } from "react-hook-form"
import type { IUser } from "@/types/user.interface"
import { Button } from "@/components/ui/button"

export default function ProfileEditForm({ user }: { user: IUser | undefined }) {

  const form = useForm({
    defaultValues: {
      username: user?.username || "",
      email: user?.email || "",
      firstName: "Иван",
      lastName: "Иванов",
    },
  })

  return (
    <Form {...form}>
      <form className="grid grid-cols-1 md:grid-cols-2 gap-6">

        <FormField
          control={form.control}
          name="firstName"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Имя</FormLabel>
              <FormControl>
                <Input
                  placeholder="Введите имя"
                  className="rounded-xl focus:ring-2 focus:ring-indigo-500 transition"
                  {...field}
                />
              </FormControl>
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="lastName"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Фамилия</FormLabel>
              <FormControl>
                <Input
                  placeholder="Введите фамилию"
                  className="rounded-xl focus:ring-2 focus:ring-indigo-500 transition"
                  {...field}
                />
              </FormControl>
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="username"
          render={({ field }) => (
            <FormItem className="md:col-span-2">
              <FormLabel>Имя пользователя</FormLabel>
              <FormControl>
                <Input
                  placeholder="Введите имя пользователя"
                  className="rounded-xl focus:ring-2 focus:ring-indigo-500 transition"
                  {...field}
                />
              </FormControl>
            </FormItem>
          )}
        />

        {/* <FormField
          control={form.control}
          name="email"
          render={({ field }) => (
            <FormItem className="md:col-span-2">
              <FormLabel>Email</FormLabel>
              <FormControl>
                <Input
                  type="email"
                  placeholder="Введите email"
                  className="rounded-xl focus:ring-2 focus:ring-indigo-500 transition"
                  {...field}
                />
              </FormControl>
            </FormItem>
          )}
        /> */}

        <div className="md:col-span-2 flex justify-end">
          <Button
            type="submit"
            className="bg-gradient-to-r from-indigo-600 to-emerald-500 text-white rounded-xl px-6 hover:scale-105 transition"
          >
            Сохранить изменения
          </Button>
        </div>

      </form>
    </Form>
  )
}