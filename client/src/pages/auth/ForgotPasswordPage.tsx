import { Button } from "@/components/ui/button"
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { useForgotPassword } from "@/shared/hooks/useUser"
import { useForm } from "react-hook-form"
export default function ForgotPasswordPage() {
    const form = useForm({ mode: "onChange" });
    const { onSubmit, isPending } = useForgotPassword();

    return (
        <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 via-white to-slate-100 p-6">
            <div className="w-full max-w-md bg-white rounded-3xl shadow-sm border p-8">
                <h1 className="text-2xl font-bold mb-2">Восстановление пароля</h1>
                <p className="text-slate-500 text-sm mb-6">
                    Введите email, и мы отправим инструкции
                </p>

                <Form {...form}>
                    <form
                        className="space-y-5"
                        onSubmit={form.handleSubmit((data) =>
                            onSubmit(data.email)
                        )}
                    >
                        <FormField
                            control={form.control}
                            name="email"
                            render={({ field }) => (
                                <FormItem>
                                    <FormLabel>Email</FormLabel>
                                    <FormControl>
                                        <Input
                                            type="email"
                                            placeholder="user@example.com"
                                            {...field}
                                            value={field.value || ""}
                                            className="h-11 rounded-xl"
                                        />
                                    </FormControl>
                                    <FormMessage />
                                </FormItem>
                            )}
                        />

                        <Button
                            type="submit"
                            disabled={isPending}
                            className="w-full h-11 rounded-xl bg-black text-white hover:bg-slate-800 transition"
                        >
                            {isPending ? "Отправка..." : "Отправить"}
                        </Button>
                    </form>
                </Form>
            </div>
        </div>
    );
}