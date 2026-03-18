import { Card, CardContent } from "@/components/ui/card"

export default function PropertyFutureFeatures() {
    return (
        <Card>

            <CardContent className="p-6 space-y-2">

                <h2 className="font-semibold">
                    Будущий функционал
                </h2>

                <p className="text-sm text-muted-foreground">
                    🔹 Галерея фотографий объекта
                </p>

                <p className="text-sm text-muted-foreground">
                    🔹 История изменений объекта
                </p>

                <p className="text-sm text-muted-foreground">
                    🔹 Связанные сделки
                </p>

                <p className="text-sm text-muted-foreground">
                    🔹 Связанные клиенты
                </p>

                <p className="text-sm text-muted-foreground">
                    🔹 Документы по объекту
                </p>

                <p className="text-sm text-muted-foreground">
                    🔹 Показ объекта (запланированные визиты)
                </p>

            </CardContent>

        </Card>
    )
}