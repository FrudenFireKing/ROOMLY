import os
import io
import base64
from flask import Flask, request, render_template, jsonify
from diffusers import StableDiffusionPipeline
from deep_translator import GoogleTranslator
import torch
import uuid
from PIL import Image
from gigachat import GigaChat
from gigachat.models import Chat
import yagmail

app = Flask(__name__)

# Инициализация переводчика
translator = GoogleTranslator(source='ru', target='en')

# Настройки Stable Diffusion
model_id = "stabilityai/stable-diffusion-2-1-base"
device = "cuda" if torch.cuda.is_available() else "cpu"

# Загрузка модели генерации изображений
pipe = StableDiffusionPipeline.from_pretrained(
    model_id,
    torch_dtype=torch.float16 if device == "cuda" else torch.float32,
    use_auth_token=False
).to(device)

# Оптимизация для GPU
if device == "cuda":
    try:
        pipe.enable_xformers_memory_efficient_attention()
        if hasattr(torch, 'compile'):
            pipe.unet = torch.compile(pipe.unet, mode="reduce-overhead", fullgraph=True)
    except:
        pass

# Инициализация GigaChat
gigachat = GigaChat(
    credentials='MWE0ZmRjZjAtNzc3ZS00Y2IwLWExYjQtMWI4MTVkYzk5YTQ4OmI0MDgyNTE2LTEyMzktNDAyYi1iZGI1LTM3NmIyZDFhN2MyZg==',
    verify_ssl_certs=False
)

# Настройки email
EMAIL_ADDRESS = "aroomly@yandex.ru"
EMAIL_PASSWORD = "adminroomly123456789"
yag = yagmail.SMTP(EMAIL_ADDRESS, EMAIL_PASSWORD)

def extract_requirements(text):
    try:
        messages = [
            {
                "role": "user",
                "content": f"""Проанализируй текст и выдели ТОЛЬКО конкретные требования к переговорной комнате. 
                Отвечай строго в формате списка без пояснений. Пример:
                - стол на 6 человек
                - проектор
                - бронирование на среду с 14:00 до 16:00

                Текст: "{text}"
                """
            }
        ]

        response = gigachat.chat(
            Chat(
                messages=messages,
                temperature=0.7,
                max_tokens=1000
            )
        )
        return [line.strip() for line in response.choices[0].message.content.split('\n') if line.strip()]
    
    except Exception as e:
        print(f"Ошибка GigaChat: {str(e)}")
        return []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate_image():
    description = request.form.get('description')
    if not description:
        return jsonify({'error': 'Описание не предоставлено'}), 400

    try:
        translated_description = translator.translate(description)
        prompt = f"Modern meeting room, {translated_description}, professional design, high quality, realistic"
        
        image = pipe(
            prompt,
            num_inference_steps=1,
            guidance_scale=7.5,
            width=512,
            height=512
        ).images[0]

        buffered = io.BytesIO()
        image.save(buffered, format="PNG")
        img_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

        return jsonify({
            'image': f'data:image/png;base64,{img_base64}',
            'status': 'Генерация завершена!'
        })

    except Exception as e:
        return jsonify({'error': f'Ошибка генерации: {str(e)}'}), 500

@app.route('/analyze', methods=['POST'])
def analyze_text():
    user_input = request.form.get('user_input')
    if not user_input:
        return jsonify({'error': 'Текст не предоставлен'}), 400
    
    requirements = extract_requirements(user_input)
    return jsonify({'requirements': requirements})

@app.route('/submit', methods=['POST'])
def submit_request():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        email = data.get('email', 'pavelsysuew06@yandex.ru')
        image_data = data.get('image')
        requirements = data.get('requirements', [])

        if not image_data or not image_data.startswith('data:image/png;base64,'):
            return jsonify({'success': False, 'error': 'Invalid image data'}), 400

        # Сохраняем временное изображение
        image_bytes = base64.b64decode(image_data.split(",")[1])
        temp_image = "temp_meeting_room.png"
        with open(temp_image, "wb") as f:
            f.write(image_bytes)

        # Отправка письма
        body = "Требования к переговорной комнате:\n\n" + "\n".join(requirements)
        yag.send(
            to=email,
            subject="Заявка на переговорную комнату",
            contents=body,
            attachments=temp_image
        )

        # Удаляем временный файл
        os.remove(temp_image)

        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)