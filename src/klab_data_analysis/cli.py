from .models import Product
from .application.product_service import ProductService


async def _choose_product(
    service: ProductService,
    product_name: str,
) -> Product | None:
    products = await service.find_products_by_name(product_name)
    if not products:
        print(f"Продукт «{product_name}» не найден.")
        return None
    if len(products) == 1:
        return products[0]

    print("Найдено несколько продуктов с таким названием:")
    for index, product in enumerate(products, start=1):
        print(f"{index}. {product.vendor} — {product.name}")

    try:
        choice = int(input("Выберите производителя по номеру: "))
    except ValueError:
        print("Нужно ввести номер из списка.")
        return None

    if not 1 <= choice <= len(products):
        print("Такого номера нет в списке.")
        return None
    return products[choice - 1]


async def _show_safe_version(service: ProductService) -> None:
    product_name = input("Название продукта: ").strip()
    if not product_name:
        print("Название продукта не должно быть пустым.")
        return

    product = await _choose_product(service, product_name)
    if product is None:
        return

    version = await service.get_safe_version(product.id)
    if version is None:
        print("Не найдено версий без известных уязвимостей.")
        return
    print(f"Версия без известных уязвимостей: {version}")


async def _show_vulnerabilities(service: ProductService) -> None:
    product_name = input("Название продукта: ").strip()
    version = input("Версия продукта: ").strip()
    if not product_name or not version:
        print("Название продукта и версия не должны быть пустыми.")
        return

    product = await _choose_product(service, product_name)
    if product is None:
        return

    try:
        vulnerabilities = await service.get_vulnerabilities_for_version(
            product.id,
            version,
        )
    except ValueError:
        print("Неверный формат версии. Пример корректного формата: 3.0.19")
        return
    if not vulnerabilities:
        print(f"Для версии {version} уязвимости в базе не найдены.")
        return

    print(f"Уязвимости продукта {product.name} версии {version}:")
    for vulnerability in vulnerabilities:
        print(f"\n{vulnerability.kla_id} ({vulnerability.publish_date:%Y-%m-%d})")
        print(f"  {vulnerability.description}")
        print(
            "  Уязвимый диапазон: "
            f"{vulnerability.start_vuln_version} – "
            f"до {vulnerability.fixed_version}"
        )


async def run_cli(service: ProductService) -> None:
    while True:
        print("\nПоиск данных об уязвимостях")
        print("1. Найти версию без известных уязвимостей")
        print("2. Показать уязвимости версии продукта")
        print("0. Выход")
        choice = input("Выберите действие: ").strip()

        if choice == "0":
            print("До свидания!")
            return
        if choice == "1":
            await _show_safe_version(service)
        elif choice == "2":
            await _show_vulnerabilities(service)
        else:
            print("Неизвестный пункт меню.")
