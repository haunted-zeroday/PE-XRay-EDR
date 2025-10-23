#define CINTERFACE
#define COBJMACROS

#include <windows.h>
#include <wincodec.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/scanner.h"
#include "core/include/pe_analyzer.h"
#include "include/resource.h"
#include <iup.h>
#include <iupim.h>
#include <iupcontrols.h>
#include <shlwapi.h>

// глобал хэндлы
static Ihandle* g_title_label = NULL;
static Ihandle* g_content_zbox = NULL;
static Ihandle* g_sidebar_list = NULL;


#define BG_COLOR            "#1e1e1e"
#define SIDEBAR_BG_COLOR    "#252526"
#define CONTENT_BG_COLOR    "#1e1e1e"
#define BORDER_COLOR        "#333333"
#define TEXT_COLOR          "#cccccc"
#define ACCENT_COLOR        "#007acc"
#define SIDEBAR_ITEM_HOVER  "#2a2d31"
#define CARD_BG_COLOR       "#2a2d31"
#define CARD_BORDER_COLOR   "#3a3d41"
#define SUSPICIOUS_BG_COLOR "120 40 40"

// глобальные переменные
static WCHAR* g_currentFilePath = NULL; //храним тут путь

// прототипы, чтобы не было конфликта из-за области видимости
int select_file_callback(Ihandle* self);
int analyze_button_callback(Ihandle* self);
void update_gui_with_results(const AnalysisResult* result);
Ihandle* create_analyzer_page();
static Ihandle* IupLoadImageFromResource_WIC(HINSTANCE hInst, int resId);
static Ihandle* IupLoadImageFromResource_Temp(HINSTANCE hInst, int resId);
static Ihandle* LoadImageFromRes(HINSTANCE hInst, int resId);

static void destroy_all_children(Ihandle* box)
{
    if (!box) return;
    // удаление всех деталей, чтобы не было утечки
    while (IupGetChildCount(box) > 0) {
        Ihandle* child = IupGetChild(box, 0);
        IupDestroy(child);
    }
}

// включить интеграцию
int enable_integration_for_type(const char* fileType, const char* exePath) {
    char command[MAX_PATH + 5];
    char iconPath[MAX_PATH + 3];
    sprintf(command, "\"%s\" \"%%1\"", exePath);
    sprintf(iconPath, "%s,0", exePath);

    HKEY hKey;
    char fullKeyPath[MAX_PATH];
    sprintf(fullKeyPath, "%s\\shell\\%s", fileType, REG_KEY_NAME);

    if (RegCreateKeyExA(HKEY_CLASSES_ROOT, fullKeyPath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        return 0;
    }

    const char* menuText = "Analyze with PE-XRay";
    RegSetValueExA(hKey, NULL, 0, REG_SZ, (const BYTE*)menuText, strlen(menuText) + 1);
    RegSetValueExA(hKey, "Icon", 0, REG_SZ, (const BYTE*)iconPath, strlen(iconPath) + 1);

    HKEY hCmdKey;
    if (RegCreateKeyExA(hKey, "command", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hCmdKey, NULL) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 0;
    }

    RegSetValueExA(hCmdKey, NULL, 0, REG_SZ, (const BYTE*)command, strlen(command) + 1);

    RegCloseKey(hCmdKey);
    RegCloseKey(hKey);

    return 1;
}

// выключить интеграцию
int disable_integration_for_type(const char* fileType) {
    char fullKeyPath[MAX_PATH];
    sprintf(fullKeyPath, "%s\\shell\\%s", fileType, REG_KEY_NAME);
    return (SHDeleteKeyA(HKEY_CLASSES_ROOT, fullKeyPath) == ERROR_SUCCESS);
}
// проверка, включена ли интеграция.
int is_integration_enabled_for_type(const char* fileType) {
    HKEY hKey;
    char fullKeyPath[MAX_PATH];
    sprintf(fullKeyPath, "%s\\shell\\%s", fileType, REG_KEY_NAME);

    if (RegOpenKeyExA(HKEY_CLASSES_ROOT, fullKeyPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 1;
    }
    return 0;
}

int is_integration_enabled_all() {
    return is_integration_enabled_for_type("exefile") && is_integration_enabled_for_type("dllfile");
}

// загрузка самих пизображений
static Ihandle* LoadImageFromRes(HINSTANCE hInst, int resId)
{
    Ihandle* img = IupLoadImageFromResource_WIC(hInst, resId);
    if (img) return img;

    img = IupLoadImageFromResource_Temp(hInst, resId);
    if (img) return img;

    // проверка, найден ли ресурс
    HRSRC hRes = FindResourceW(hInst, MAKEINTRESOURCEW(resId), L"RCDATA");
    if (!hRes) {
        char msg[128];
        sprintf(msg, "FindResourceW RCDATA id=%d failed", resId);
        MessageBoxA(NULL, msg, "RES", MB_ICONERROR);
    }
    return NULL;
}

// создание ключа из регистра
int enable_integration_all() {
    char exePath[MAX_PATH];
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH) == 0) {
        return 0;
    }
    int success_exe = enable_integration_for_type("exefile", exePath);
    int success_dll = enable_integration_for_type("dllfile", exePath);
    return success_exe && success_dll;
}

// удаление ключа из регистра
int disable_integration_all() {
    int success_exe = disable_integration_for_type("exefile");
    int success_dll = disable_integration_for_type("dllfile");
    return success_exe && success_dll;
}

// загружаем во временную папку
static Ihandle* IupLoadImageFromResource_Temp(HINSTANCE hInst, int resId)
{
    HRSRC hRes = FindResource(hInst, MAKEINTRESOURCE(resId), RT_RCDATA);
    if (!hRes) return NULL;

    DWORD sz = SizeofResource(hInst, hRes);
    HGLOBAL hData = LoadResource(hInst, hRes);
    if (!hData) return NULL;

    void* pData = LockResource(hData);
    if (!pData || sz == 0) return NULL;

    wchar_t tempPath[MAX_PATH], tempFile[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    GetTempFileNameW(tempPath, L"png", 0, tempFile);

    HANDLE f = CreateFileW(tempFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (f == INVALID_HANDLE_VALUE) return NULL;

    DWORD written = 0;
    BOOL ok = WriteFile(f, pData, sz, &written, NULL);
    CloseHandle(f);
    if (!ok || written != sz) { DeleteFileW(tempFile); return NULL; }

    char* path_utf8 = ConvertWcharToUtf8(tempFile);
    Ihandle* img = NULL;
    if (path_utf8) {
        img = IupLoadImage(path_utf8);
        free(path_utf8);
    }

    DeleteFileW(tempFile);
    return img;
}

//загрузка изображений из ресурсов
static Ihandle* IupLoadImageFromResource_WIC(HINSTANCE hInst, int resId)
{
    HRSRC hRes = NULL;
    HGLOBAL hData = NULL;
    BYTE* pData = NULL;
    DWORD sz = 0;
    HRESULT hr = E_FAIL;
    IWICImagingFactory* factory = NULL;
    IWICStream* stream = NULL;
    IWICBitmapDecoder* decoder = NULL;
    IWICBitmapFrameDecode* frame = NULL;
    IWICFormatConverter* conv = NULL;

    UINT w = 0, h = 0;
    size_t bufSize = 0;
    BYTE* pixels = NULL;
    Ihandle* img = NULL;
    hRes = FindResource(hInst, MAKEINTRESOURCE(resId), RT_RCDATA);
    if (!hRes) goto cleanup;

    sz = SizeofResource(hInst, hRes);
    hData = LoadResource(hInst, hRes);
    if (!hData) goto cleanup;

    pData = (BYTE*)LockResource(hData);
    if (!pData || sz == 0) goto cleanup;

    hr = CoCreateInstance(CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER,
                        IID_IWICImagingFactory, (void**)&factory);
    if (FAILED(hr)) goto cleanup;

    hr = IWICImagingFactory_CreateStream(factory, &stream);
    if (FAILED(hr)) goto cleanup;

    hr = IWICStream_InitializeFromMemory(stream, pData, sz);
    if (FAILED(hr)) goto cleanup;

    hr = IWICImagingFactory_CreateDecoderFromStream(factory, (IStream*)stream, NULL,
        WICDecodeMetadataCacheOnLoad, &decoder);
    if (FAILED(hr)) goto cleanup;

    hr = IWICBitmapDecoder_GetFrame(decoder, 0, &frame);
    if (FAILED(hr)) goto cleanup;

    hr = IWICImagingFactory_CreateFormatConverter(factory, &conv);
    if (FAILED(hr)) goto cleanup;

    hr = IWICFormatConverter_Initialize(conv, (IWICBitmapSource*)frame,
        GUID_WICPixelFormat32bppRGBA, WICBitmapDitherTypeNone, NULL, 0.0,
        WICBitmapPaletteTypeCustom);
    if (FAILED(hr)) goto cleanup;

    hr = IWICFormatConverter_GetSize(conv, &w, &h);
    if (FAILED(hr)) goto cleanup;

    bufSize = (size_t)w * (size_t)h * 4;
    pixels = (BYTE*)malloc(bufSize);
    if (!pixels) goto cleanup;

    hr = IWICFormatConverter_CopyPixels(conv, NULL, w * 4, (UINT)bufSize, pixels);
    if (FAILED(hr)) goto cleanup;

    img = IupImageRGBA((int)w, (int)h, pixels);
    cleanup:
    if (pixels) { free(pixels); pixels = NULL; }
    if (conv) IWICFormatConverter_Release(conv);
    if (frame) IWICBitmapFrameDecode_Release(frame);
    if (decoder) IWICBitmapDecoder_Release(decoder);
    if (stream) IWICStream_Release(stream);
    if (factory) IWICImagingFactory_Release(factory);


    return img;
}

// колбэки
int select_file_callback(Ihandle* self) {
    WCHAR file_path_wchar[MAX_PATH] = { 0 };
    OPENFILENAMEW ofn = { 0 };
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = IupGetDialog(self) ? (HWND)IupGetAttribute(IupGetDialog(self), "HWND") : NULL;
    ofn.lpstrFile = file_path_wchar;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"Исполняемые файлы (*.exe;*.dll)\0*.exe;*.dll\0Все файлы (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrTitle = L"Выберите файл для анализа";
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;

    if (GetOpenFileNameW(&ofn)) {
        if (g_currentFilePath) {
            free(g_currentFilePath);
        }
        g_currentFilePath = _wcsdup(file_path_wchar);

        char* path_utf8 = ConvertWcharToUtf8(g_currentFilePath);
        if (path_utf8) {
            Ihandle* path_text = IupGetHandle("path_text");
            if (path_text) {
                IupSetStrAttribute(path_text, "VALUE", path_utf8);
            }
            free(path_utf8);
        }
    }
    return IUP_DEFAULT;
}

int toggle_integration_cb(Ihandle* self) {
    int is_checked = IupGetInt(self, "VALUE");
    const char* admin_msg = "\n\nВозможно, требуется запустить программу от имени Администратора.";

    if (is_checked) {
        if (enable_integration_all()) {
            IupMessage("Success", "Интеграция в контекстное меню включена.");
        } else {
            char msg[256];
            sprintf(msg, "Не удалось включить интеграцию.%s", admin_msg);
            IupMessage("Error", msg);
            IupSetAttribute(self, "VALUE", "OFF");
        }
    } else {
        if (disable_integration_all()) {
            IupMessage("Success", "Интеграция в контекстное меню отключена.");
        } else {
            char msg[256];
            sprintf(msg, "Не удалось отключить интеграцию.%s", admin_msg);
            IupMessage("Ошибка!", msg);
            IupSetAttribute(self, "VALUE", "ON");
        }
    }
    return IUP_DEFAULT;
}

int analyze_button_callback(Ihandle* self) {
    if (!g_currentFilePath || g_currentFilePath[0] == L'\0') {
        IupMessage("Внимание", "Пожалуйста, сначала выберите файл.");
        return IUP_DEFAULT;
    }

    Ihandle* main_dialog = IupGetDialog(self);
    Ihandle* status_label = IupGetHandle("status_label");

    // чистка гуишки
    update_gui_with_results(NULL); 
    if (status_label) IupSetAttribute(status_label, "TITLE", "Анализ...");
    IupSetAttribute(main_dialog, "ACTIVE", "NO");
    IupFlush();

    // запуск самого анализа
    static AnalysisResult result_data;
    free_analysis_result(&result_data); // чистим от прошлого анализа
    memset(&result_data, 0, sizeof(AnalysisResult));

    if (analyze_pe_file(g_currentFilePath, &result_data)) {
        update_gui_with_results(&result_data);
        if (status_label) IupSetAttribute(status_label, "TITLE", "Анализ завершен.");
    } else {
        Ihandle* verdict_label = IupGetHandle("verdict_label");
        if (verdict_label) IupSetAttribute(verdict_label, "TITLE", "Вердикт: Ошибка анализа файла!");
        if (status_label) IupSetAttribute(status_label, "TITLE", "Ошибка.");
    }

    IupSetAttribute(main_dialog, "ACTIVE", "YES");
    return IUP_DEFAULT;
}

void update_gui_with_results(const AnalysisResult* result) 
{
    Ihandle* verdict_label = IupGetHandle("verdict_label");
    Ihandle* score_label = IupGetHandle("score_label");
    Ihandle* findings_text = IupGetHandle("findings_text");
    Ihandle* sections_list_vbox = IupGetHandle("sections_list_vbox");
    Ihandle* imports_tree = IupGetHandle("imports_tree");

    // чиста всего ненужного
    if (!result) {
        if (verdict_label) IupSetAttribute(verdict_label, "TITLE", "Вердикт: ...                            ");
        if (score_label)   IupSetAttribute(score_label, "TITLE", "Счет: ...       ");
        if (findings_text) IupSetAttribute(findings_text, "VALUE", "");
        
        if (sections_list_vbox) {
            destroy_all_children(sections_list_vbox);
            IupRefresh(sections_list_vbox);
        }
        //чистка древа импорта
        if (imports_tree) {
            IupSetAttribute(imports_tree, "DELNODE", "CHILDREN");
        }

        if(verdict_label) IupRefresh(IupGetDialog(verdict_label));
        return;
    }


    // заполнение "сводный отчет"
    if (verdict_label) IupSetfAttribute(verdict_label, "TITLE", "Вердикт: %s", result->verdict);
    if (score_label)   IupSetfAttribute(score_label, "TITLE", "Счет: %d", result->total_score);

    if (findings_text) {
        char report_buffer[8192] = { 0 };
        for (int i = 0; i < result->finding_count; i++) {
            if (strlen(report_buffer) + strlen(result->findings[i].description) + 20 < sizeof(report_buffer)) {
                char line[1024];
                sprintf(line, "- [%d pts] %s\n", result->findings[i].score, result->findings[i].description);
                strcat(report_buffer, line);
            }
        }
        IupSetStrAttribute(findings_text, "VALUE", report_buffer);
    }

    // заполняем данными вкладку "Секции"
    if (sections_list_vbox)
    {
        destroy_all_children(sections_list_vbox);

        if (result && result->sections && result->section_count > 0)
        {
            const char* col_widths[] = { "120x", "100x", "100x", "80x", "60x" };

            char buffer[64];
            for (int i = 0; i < result->section_count; i++)
            {
                Ihandle* label_name = IupLabel(result->sections[i].name);

                sprintf(buffer, "0x%08X", result->sections[i].virtual_address);
                Ihandle* label_addr = IupLabel(buffer);

                sprintf(buffer, "%u", result->sections[i].virtual_size);
                Ihandle* label_size = IupLabel(buffer);

                sprintf(buffer, "%.2f", result->sections[i].entropy);
                Ihandle* label_entr = IupLabel(buffer);

                Ihandle* label_flags = IupLabel(result->sections[i].flags);

                Ihandle* row_hbox = IupHbox(label_name, label_addr, label_size, label_entr, label_flags, NULL);
                IupSetAttribute(row_hbox, "GAP", "10");
                IupSetAttribute(row_hbox, "ALIGNMENT", "ACENTER");
                IupSetAttribute(row_hbox, "EXPAND", "HORIZONTAL");

                Ihandle* row_cells[] = { label_name, label_addr, label_size, label_entr, label_flags };
                for (int j = 0; j < 5; j++) {
                    IupSetAttribute(row_cells[j], "SIZE", col_widths[j]);
                    IupSetAttribute(row_cells[j], "ALIGNMENT", "ALEFT");
                    IupSetAttribute(row_cells[j], "FGCOLOR", TEXT_COLOR);
                }

                if (result->sections[i].is_suspicious) {
                    IupSetAttribute(row_hbox, "BGCOLOR", SUSPICIOUS_BG_COLOR);
                }
                IupAppend(sections_list_vbox, row_hbox);
                IupMap(row_hbox);
            }
        }

        IupRefresh(sections_list_vbox);
        Ihandle* dlg = IupGetDialog(sections_list_vbox);
        if (dlg) IupRefresh(dlg);
    }

    // заполнение секции "импорты"
    if (imports_tree && result->dll_count > 0)
    {
        IupSetAttribute(imports_tree, "DELNODE", "CHILDREN");
        char attr[64];

        for (int i = 0; i < result->dll_count; ++i)
        {
            const char* dll_name = result->dlls[i].name;
            if (!dll_name || !dll_name[0]) dll_name = "(unknown DLL)";

            IupSetAttribute(imports_tree, "ADDBRANCH-1", dll_name);
            int dll_id = IupGetInt(imports_tree, "LASTADDNODE_ID");

            for (int j = 0; j < result->dlls[i].function_count; ++j)
            {
                const char* func_name = result->dlls[i].functions[j].name;
                if (!func_name || !func_name[0]) func_name = "(unnamed)";

                sprintf(attr, "ADDLEAF%d", dll_id);
                IupSetAttribute(imports_tree, attr, func_name);

                if (result->dlls[i].functions[j].is_suspicious)
                {
                    int func_id = IupGetInt(imports_tree, "LASTADDNODE_ID");
                    sprintf(attr, "FGCOLOR%d", func_id);
                    IupSetAttribute(imports_tree, attr, "255 100 100");
                }
            }
        }

        IupRefreshChildren(IupGetDialog(imports_tree));
    }


    Ihandle* main_dialog = IupGetDialog(verdict_label);
    if (main_dialog) IupRefreshChildren(main_dialog);
}

Ihandle* create_result_tabs()
{
    // начало вкладки "сводный отчет" 
    Ihandle* verdict_label = IupLabel("Вердикт: ...");
    IupSetAttribute(verdict_label, "FONT", ", Bold 14");
    IupSetAttribute(verdict_label, "FGCOLOR", TEXT_COLOR);

    Ihandle* score_label = IupLabel("Счет: ...");
    IupSetAttribute(score_label, "FGCOLOR", TEXT_COLOR);

    Ihandle* findings_text = IupText(NULL);
    IupSetAttribute(findings_text, "MULTILINE", "YES");
    IupSetAttribute(findings_text, "EXPAND", "YES");
    IupSetAttribute(findings_text, "READONLY", "YES");
    IupSetAttribute(findings_text, "BGCOLOR", CONTENT_BG_COLOR);
    IupSetAttribute(findings_text, "FGCOLOR", TEXT_COLOR);
    IupSetAttribute(findings_text, "BORDER", "NO");
    IupSetAttribute(findings_text, "PADDING", "5x5");

    Ihandle* summary_vbox = IupVbox(verdict_label, score_label, IupSetAttributes(IupFill(), "RASTERSIZE=x10"), findings_text, NULL);
    IupSetAttribute(summary_vbox, "GAP", "5");
    IupSetAttribute(summary_vbox, "MARGIN", "10x10");

    // начало вкладки "секции"
    
    const char* col_widths[] = { "120", "100", "100", "80", "60" };

    // шапка таблицы для секций
    Ihandle* header_name = IupLabel("Имя");
    Ihandle* header_addr = IupLabel("Адрес");
    Ihandle* header_size = IupLabel("Размер");
    Ihandle* header_entropy = IupLabel("Энтропия");
    Ihandle* header_flags = IupLabel("Флаги");

    Ihandle* headers_array[] = { header_name, header_addr, header_size, header_entropy, header_flags };
    for (int i = 0; i < 5; i++) {
        IupSetAttribute(headers_array[i], "FONT", ", Bold");
        IupSetAttribute(headers_array[i], "FGCOLOR", TEXT_COLOR);
        IupSetAttribute(headers_array[i], "SIZE", col_widths[i]); // Задаем ширину
        IupSetAttribute(headers_array[i], "ALIGNMENT", "ALEFT");
    }

    Ihandle* headers_hbox = IupHbox(header_name, header_addr, header_size, header_entropy, header_flags, NULL);
    IupSetAttribute(headers_hbox, "GAP", "10");
    IupSetAttribute(headers_hbox, "ALIGNMENT", "ACENTER");

    Ihandle* sections_list_vbox = IupVbox(NULL);
    IupSetAttribute(sections_list_vbox, "GAP", "3");
    IupSetAttribute(sections_list_vbox, "MARGIN", "0x5");

    Ihandle* sections_scrollbox = IupScrollBox(sections_list_vbox);
    IupSetAttribute(sections_scrollbox, "EXPAND", "YES");
    IupSetAttribute(sections_scrollbox, "BGCOLOR", CONTENT_BG_COLOR);

    // сбор финальной страницы "секции"
    Ihandle* sections_page = IupVbox(
        headers_hbox,
        IupLabel(NULL),
        sections_scrollbox,
        NULL
    );
    IupSetAttribute(sections_page, "MARGIN", "10x10");
    IupSetAttribute(sections_page, "GAP", "5");
        
    // создание элементов "Импорты"
    Ihandle* imports_tree = IupTree();
    IupSetAttribute(imports_tree, "SHOWRENAME", "NO");
    IupSetAttribute(imports_tree, "EXPAND", "YES");
    IupSetAttribute(imports_tree, "BGCOLOR", CONTENT_BG_COLOR);
    IupSetAttribute(imports_tree, "FGCOLOR", TEXT_COLOR);
    IupSetAttribute(imports_tree, "BORDER", "NO");

    Ihandle* result_tabs = IupTabs(summary_vbox, sections_page, imports_tree, NULL);
	IupSetAttribute(result_tabs, "TABSFGCOLOR", TEXT_COLOR); 
	IupSetAttribute(result_tabs, "TABSBGCOLOR", SIDEBAR_BG_COLOR);
    IupSetAttribute(result_tabs, "TABTITLE0", "Сводный отчет");
    IupSetAttribute(result_tabs, "TABTITLE1", "Секции");
    IupSetAttribute(result_tabs, "TABTITLE2", "Импорты");
    IupSetAttribute(result_tabs, "BGCOLOR", CARD_BG_COLOR);
    
    IupSetHandle("verdict_label", verdict_label);
    IupSetHandle("score_label", score_label);
    IupSetHandle("findings_text", findings_text);
    IupSetHandle("sections_list_vbox", sections_list_vbox);
    IupSetHandle("imports_tree", imports_tree);

    return result_tabs;
}

// создает страницу для анализа
Ihandle* create_analyzer_page() {
    Ihandle* filepath_text = IupText(NULL);
    IupSetAttribute(filepath_text, "READONLY", "YES");
    IupSetAttribute(filepath_text, "EXPAND", "HORIZONTAL");
    IupSetAttribute(filepath_text, "BGCOLOR", "#2d2d30");
    IupSetAttribute(filepath_text, "FGCOLOR", TEXT_COLOR);
    IupSetAttribute(filepath_text, "BORDER", "NO");
    IupSetAttribute(filepath_text, "PADDING", "5x5");
    IupSetHandle("path_text", filepath_text);

    Ihandle* select_file_button = IupButton("Выбрать файл...", NULL);
    IupSetCallback(select_file_button, "ACTION", (Icallback)select_file_callback);
    IupSetAttribute(select_file_button, "FLAT", "YES");
    IupSetAttribute(select_file_button, "PADDING", "4x2");
    IupSetAttribute(select_file_button, "FGCOLOR", TEXT_COLOR);
    
    Ihandle* analyze_button = IupButton("Анализировать", NULL);
    IupSetCallback(analyze_button, "ACTION", (Icallback)analyze_button_callback);
    IupSetAttribute(analyze_button, "FLAT", "YES");
    IupSetAttribute(analyze_button, "PADDING", "4x2");
    IupSetAttribute(analyze_button, "FGCOLOR", TEXT_COLOR);

    Ihandle* top_hbox = IupHbox(filepath_text, select_file_button, analyze_button, NULL);
    IupSetAttribute(top_hbox, "GAP", "10");
    IupSetAttribute(top_hbox, "MARGIN", "0x10");

    Ihandle* result_tabs = create_result_tabs();

    Ihandle* page_vbox = IupVbox(top_hbox, result_tabs, NULL);
    return page_vbox;
}

// для главной страницы и настроек.
Ihandle* make_card(const char* title, Ihandle* content) {
    Ihandle* title_label = IupLabel(title);
    IupSetAttribute(title_label, "FONT", ", Bold 12");
    IupSetAttribute(title_label, "FGCOLOR", TEXT_COLOR);
    IupSetAttribute(title_label, "PADDING", "0x5");

    Ihandle* separator = IupLabel(NULL);
    IupSetAttribute(separator, "SEPARATOR", "HORIZONTAL");
    IupSetAttribute(separator, "COLOR", BORDER_COLOR);

    Ihandle* vbox = IupVbox(
        title_label,
        separator,
        IupSetAttributes(IupFill(), "RASTERSIZE=x10"),
        content,
        NULL
    );
    IupSetAttribute(vbox, "MARGIN", "10x10");
    IupSetAttribute(vbox, "GAP", "5");

    Ihandle* frame = IupFrame(vbox);
    IupSetAttribute(frame, "FGCOLOR", CARD_BORDER_COLOR);
    IupSetAttribute(frame, "BGCOLOR", CARD_BG_COLOR);
    return frame;
}

/*      колбэк для перехода в другую секцию      */
int nav_enter_cb(Ihandle* self) {
    if (IupGetInt(self, "ACTIVE_ON")) return IUP_DEFAULT;
    IupSetAttribute(self, "BGCOLOR", SIDEBAR_ITEM_HOVER);
    return IUP_DEFAULT;
}


/*      колбэк для перехода в другую секцию      */
int nav_leave_cb(Ihandle* self) {
    if (IupGetInt(self, "ACTIVE_ON")) return IUP_DEFAULT;
    IupSetAttribute(self, "BGCOLOR", NULL);
    return IUP_DEFAULT;
}

/*  чистка всех индикаторов */
void clear_all_indicators() {
    int count = IupGetChildCount(g_sidebar_list);
    for (int i = 0; i < count; i++) {
        Ihandle* hbox_item = IupGetChild(g_sidebar_list, i);
        Ihandle* indicator = IupGetChild(hbox_item, 0);
        Ihandle* button = IupGetChild(hbox_item, 1);
        if (indicator && button) {
            IupSetAttribute(indicator, "RASTERSIZE", "0x");
            IupSetAttribute(button, "BGCOLOR", NULL);
            IupSetAttribute(button, "ACTIVE_ON", "0");
        }
    }
}
/*      колбэк для перехода в другую секцию      */
int nav_click_cb(Ihandle* self) {
    Ihandle* page = IupGetAttributeHandle(self, "TARGET_PAGE");
    const char* title = IupGetAttribute(self, "TITLE");
    if (page && g_content_zbox) {
        IupSetAttribute(g_content_zbox, "VALUEPOS", IupGetAttribute(self, "PAGE_INDEX"));
    }
    clear_all_indicators();

    Ihandle* hbox_item = IupGetParent(self);
    Ihandle* indicator = IupGetChild(hbox_item, 0);
    IupSetAttribute(indicator, "RASTERSIZE", "3x");
    IupSetAttribute(self, "BGCOLOR", SIDEBAR_ITEM_HOVER);
    IupSetAttribute(self, "ACTIVE_ON", "1");

    IupSetfAttribute(g_title_label, "TITLE", "Раздел: %s", title ? title : "");

    return IUP_DEFAULT;
}

/*                         переход в другую вкладку                 */
Ihandle* make_nav_item(const char* title, const char* image, const char* page_index, Ihandle* target_page) {
    Ihandle* indicator = IupLabel(NULL);
    IupSetAttribute(indicator, "RASTERSIZE", "0x");
    IupSetAttribute(indicator, "BGCOLOR", ACCENT_COLOR);

    Ihandle* button = IupButton(title, NULL);
    IupSetAttribute(button, "FLAT", "YES");
    IupSetAttribute(button, "ALIGNMENT", "ALEFT:ACENTER");
    IupSetAttribute(button, "FGCOLOR", TEXT_COLOR);
    IupSetAttribute(button, "IMAGE", image);
    IupSetAttribute(button, "IMAGEPOSITION", "LEFT");
    IupSetAttribute(button, "GAP", "12");
    IupSetAttribute(button, "PADDING", "10x10");
    IupSetAttribute(button, "EXPAND", "HORIZONTAL");
    IupSetAttribute(button, "PAGE_INDEX", page_index);
    IupSetAttributeHandle(button, "TARGET_PAGE", target_page);
    IupSetCallback(button, "ACTION", (Icallback)nav_click_cb);
    IupSetCallback(button, "ENTERWINDOW_CB", (Icallback)nav_enter_cb);
    IupSetCallback(button, "LEAVEWINDOW_CB", (Icallback)nav_leave_cb);

    Ihandle* hbox = IupHbox(indicator, button, NULL);
    IupSetAttribute(hbox, "ALIGNMENT", "ACENTER");
    IupSetAttribute(hbox, "GAP", "8");
    return hbox;
}


/*          Entrypoint          */
int main(int argc, char** argv) {
    HRESULT cohr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        if (FAILED(cohr)) {
        MessageBoxA(NULL, "CoInitializeEx failed (WIC)", "Error", MB_ICONERROR);
        return 1;
    }
    IupOpen(&argc, &argv);
    IupImageLibOpen();

    IupSetGlobal("UTF8MODE", "YES");
    IupSetAttribute(IupGetHandle("GLOBAL"), "FONT", "Segoe UI, 10");
    HINSTANCE hInst = GetModuleHandle(NULL);
    
    // icons (32x32)
    IupSetHandle("imgHome",      LoadImageFromRes(hInst, IDR_PNG_HOME));
    IupSetHandle("imgAnalytics", LoadImageFromRes(hInst, IDR_PNG_ANALYTICS));
    IupSetHandle("imgSettings",  LoadImageFromRes(hInst, IDR_PNG_SETTINGS));
    IupSetHandle("imgExit",      LoadImageFromRes(hInst, IDR_PNG_EXIT));
    IupSetHandle("imgLogo",      LoadImageFromRes(hInst, IDR_PNG_LOGO));
    
    Ihandle* page_home = IupLabel("Добро пожаловать в PE-XRay!\n\nВыберите раздел 'Аналитика', чтобы начать.");
    IupSetAttribute(page_home, "EXPAND", "YES");
    IupSetAttribute(page_home, "ALIGNMENT", "ACENTER");
    IupSetAttribute(page_home, "FGCOLOR", TEXT_COLOR);

    Ihandle* page_analyzer = create_analyzer_page();

    // интеграция
    Ihandle* integration_toggle = IupToggle("Включить интеграцию в контекстное меню (для .exe и .dll)", NULL);
    IupSetCallback(integration_toggle, "ACTION", (Icallback)toggle_integration_cb);
    IupSetAttribute(integration_toggle, "FGCOLOR", TEXT_COLOR);

    if (is_integration_enabled_all()) {
        IupSetAttribute(integration_toggle, "VALUE", "ON");
    }

    Ihandle* settings_content = IupVbox(integration_toggle, NULL);
    IupSetAttribute(settings_content, "MARGIN", "10x5");
    IupSetAttribute(settings_content, "GAP", "10");

    g_content_zbox = IupZbox(page_home, page_analyzer, settings_content, NULL);
    // левая панель
    Ihandle* logo_label = IupLabel("PE-XRay Analyse");
    IupSetAttribute(logo_label, "FONT", ", Bold 11");
    IupSetAttribute(logo_label, "FGCOLOR", TEXT_COLOR);
    Ihandle* logo_icon = IupLabel(NULL);
    IupSetAttribute(logo_icon, "IMAGE", "imgLogo");
    Ihandle* logo_area = IupHbox(logo_icon, logo_label, NULL);
    IupSetAttribute(logo_area, "ALIGNMENT", "ACENTER");
    IupSetAttribute(logo_area, "GAP", "10");

    Ihandle* separator_top = IupLabel(NULL);
    IupSetAttribute(separator_top, "SEPARATOR", "HORIZONTAL");
    IupSetAttribute(separator_top, "COLOR", BORDER_COLOR);
    
    Ihandle* nav_home = make_nav_item("Главная", "imgHome", "0", page_home);
    Ihandle* nav_analytics = make_nav_item("Аналитика", "imgAnalytics", "1", page_analyzer);
    Ihandle* nav_settings = make_nav_item("Настройки", "imgSettings", "2", settings_content);
    
    Ihandle* nav_exit_btn = IupButton("Выход", NULL);
    IupSetAttribute(nav_exit_btn, "FGCOLOR", TEXT_COLOR);
    IupSetAttribute(nav_exit_btn, "IMAGE", "imgExit");
    IupSetAttribute(nav_exit_btn, "FLAT", "YES");
    IupSetAttribute(nav_exit_btn, "PADDING", "10x10");
    IupSetCallback(nav_exit_btn, "ACTION", (Icallback)IupExitLoop);
    
    g_sidebar_list = IupVbox( nav_home, nav_analytics, nav_settings, NULL );
    IupSetAttribute(g_sidebar_list, "GAP", "5");

    Ihandle* sidebar = IupVbox( logo_area, separator_top, g_sidebar_list, IupFill(), nav_exit_btn, NULL );
    IupSetAttribute(sidebar, "MARGIN", "8x8");
    IupSetAttribute(sidebar, "GAP", "15");
    IupSetAttribute(sidebar, "BGCOLOR", SIDEBAR_BG_COLOR);

    // правая панель
    g_title_label = IupLabel("Раздел: Главная");
    IupSetAttribute(g_title_label, "FONT", ", Bold 18");
    IupSetAttribute(g_title_label, "FGCOLOR", TEXT_COLOR);
    IupSetAttribute(g_title_label, "EXPAND", "HORIZONTAL");

    Ihandle* content = IupVbox( g_title_label, IupSetAttributes(IupFill(), "RASTERSIZE=x25"), g_content_zbox, NULL );
    IupSetAttribute(content, "MARGIN", "30x30");
    IupSetAttribute(content, "BGCOLOR", CONTENT_BG_COLOR);
    IupSetAttribute(content, "EXPAND", "YES");

    Ihandle* split = IupSplit(sidebar, content);
    IupSetAttribute(split, "ORIENTATION", "VERTICAL");
    IupSetAttribute(split, "COLOR", BORDER_COLOR);
    IupSetAttribute(split, "BARSIZE", "1");
    IupSetAttribute(split, "SHOWGRIP", "NO");
    IupSetAttribute(split, "VALUE", "200");
    IupSetAttribute(split, "MINMAX", "180:350");

    Ihandle* dialog = IupDialog(split);
    IupSetAttribute(dialog, "TITLE", "PE-XRay");
    IupSetAttribute(dialog, "RASTERSIZE", "1280x600");
    IupSetAttribute(dialog, "BGCOLOR", BG_COLOR);
    IupSetAttribute(dialog, "ICON", "IDI_APP_ICON");

    // установка основной страницы "аналитика" если в параметры передается путь файла
    if (argc > 1) {
        Ihandle* analytics_button = IupGetChild(nav_analytics, 1);
        if (analytics_button) {
            nav_click_cb(analytics_button);
        }
    } else {
        Ihandle* home_button = IupGetChild(nav_home, 1);
        if (home_button) {
            nav_click_cb(home_button);
        }
    }

    IupShowXY(dialog, IUP_CENTER, IUP_CENTER);

    if (argc > 1) {
        WCHAR* path_wchar = ConvertUtf8ToWchar(argv[1]);
        if (path_wchar) {
            if (g_currentFilePath) free(g_currentFilePath);
            g_currentFilePath = _wcsdup(path_wchar);
            
            Ihandle* path_text = IupGetHandle("path_text");
            if (path_text) {
                IupSetStrAttribute(path_text, "VALUE", argv[1]);
            }
            free(path_wchar);
        }

        Ihandle* analytics_button = IupGetChild(nav_analytics, 1);
        if (analytics_button) {
            nav_click_cb(analytics_button);
        }

        Ihandle* analyze_button = IupGetHandle("path_text");
        if (analyze_button) {
            analyze_button_callback(analyze_button);
        }
    }

    IupMainLoop();
    if (g_currentFilePath) free(g_currentFilePath);
    IupClose();
    CoUninitialize();
    return 0;
}